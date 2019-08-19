package child

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"sync"

	"github.com/ilyaluk/bastion/internal/client"
	"github.com/ilyaluk/bastion/internal/config"
	"github.com/ilyaluk/bastion/internal/requests"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Server implements SSH server that connects to user
type Server struct {
	Conf config.Child
	*zap.SugaredLogger

	username       string
	sessId         []byte
	noMoreSessions bool
	sshConn        *ssh.ServerConn
	agent          *ClientAgent
	clientProvider *client.Provider
}

type ClientAgent struct {
	*zap.SugaredLogger
	sshConn *ssh.ServerConn
	ch      ssh.Channel
	refs    int
	refsMu  sync.Mutex
}

func (ca *ClientAgent) Get() (am ssh.AuthMethod, err error) {
	ca.refsMu.Lock()
	defer ca.refsMu.Unlock()

	ca.refs++

	ca.Info("opening auth-agent channel")
	ch, reqs, err := ca.sshConn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return
	}
	ca.Info("opened auth-agent channel")
	ca.ch = ch

	// probably no requests here whatsoever
	go ssh.DiscardRequests(reqs)

	am = ssh.PublicKeysCallback(agent.NewClient(ch).Signers)
	return
}

func (ca *ClientAgent) Close() {
	ca.refsMu.Lock()
	defer ca.refsMu.Unlock()

	ca.refs--
	ca.Infow("decreased refs on client agent", "refs", ca.refs)
	if ca.refs == 0 {
		ca.ch.Close()
	}
}

func (s *Server) readHostKey() (sign ssh.Signer, err error) {
	privateBytes, err := ioutil.ReadFile(s.Conf.HostKey)
	if err != nil {
		return
	}
	return ssh.ParsePrivateKey(privateBytes)
}

func readAuthorizedKeys(fname string) (map[string]bool, error) {
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	ak := map[string]bool{}
	for len(data) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, err
		}

		ak[string(pubKey.Marshal())] = true
		data = rest
	}

	return ak, nil
}

func (s *Server) authCallback(sc ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	usr, err := user.Lookup(sc.User())
	if err != nil {
		return nil, errors.Wrap(err, "cannot lookup user")
	}
	if usr.HomeDir == "" {
		return nil, errors.New("user have no homedir")
	}
	ak, err := readAuthorizedKeys(fmt.Sprintf("%s/.ssh/authorized_keys", usr.HomeDir))
	if err != nil {
		return nil, errors.Wrap(err, "cannot read authorized_keys")
	}

	fp := ssh.FingerprintSHA256(pubKey)
	if ak[string(pubKey.Marshal())] {
		s.Infow("client offered valid key",
			"user", sc.User(),
			"pubkey-fp", fp,
			"sessid", sc.SessionID(),
		)
		return &ssh.Permissions{
			Extensions: map[string]string{
				"pubkey-fp": fp,
			},
		}, nil
	}
	s.Infow("client offered invalid key",
		"user", sc.User(),
		"pubkey-fp", fp,
		"sessid", sc.SessionID(),
	)
	return nil, fmt.Errorf("unknown public key for %q", sc.User())
}

func (s *Server) handleGlobalReqs(reqs <-chan *ssh.Request) {
	for req := range reqs {
		s.Infow("global request", "req", req)
		switch req.Type {
		case "keepalive@openssh.com":
			req.Reply(true, nil)
		// TODO: race condition because of this
		// case "no-more-sessions@openssh.com":
		// 	s.noMoreSessions = true
		default:
			// "[cancel-]tcpip-forward" falls here
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (s *Server) handleChannels(chans <-chan ssh.NewChannel, errs chan<- error) {
	for ch := range chans {
		s.Infow("new channel request", "type", ch.ChannelType())
		switch ch.ChannelType() {
		case "session":
			if s.noMoreSessions {
				ch.Reject(ssh.Prohibited, "no-more-sessions was sent")
				continue
			}

			go HandleSession(ch, &sessionConfig{
				SugaredLogger: s.SugaredLogger,
				conf:          s.Conf,
				errs:          errs,
				agent:         s.agent,
				username:      s.username,
				sessId:        s.sessId,
				clientProv:    s.clientProvider,
			})

		case "direct-tcpip":
			var tcpForwardReq requests.ChannelOpenDirectMsg
			if err := ssh.Unmarshal(ch.ExtraData(), &tcpForwardReq); err != nil {
				errs <- errors.Wrap(err, "error parsing tcpip request")
				continue
			}
			s.Infow("tcpip request", "req", tcpForwardReq)

			go HandleTCP(ch, &tcpConfig{
				channelConfig: channelConfig{
					SugaredLogger: s.SugaredLogger,
					conf:          s.Conf,
					errs:          errs,
					agent:         s.agent,
					username:      s.username,
					sessId:        s.sessId,
					clientProv:    s.clientProvider,
				},
				srcHost: tcpForwardReq.LAddr,
				srcPort: uint16(tcpForwardReq.LPort),
				dstHost: tcpForwardReq.RAddr,
				dstPort: uint16(tcpForwardReq.RPort),
			})

		case "x11", "forwarded-tcpip", "tun@openssh.com", "direct-streamlocal@openssh.com", "forwarded-streamlocal@openssh.com":
			ch.Reject(ssh.Prohibited, fmt.Sprintf("using %s is prohibited", ch.ChannelType()))
		default:
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}

	close(errs)
}

func (s *Server) ProcessConnection() (err error) {
	// create client connection from fd
	nConn, err := net.FileConn(os.NewFile(3, "nConn"))
	for err != nil {
		return errors.Wrap(err, "failed to create client conn")
	}
	defer nConn.Close()

	hostKey, err := s.readHostKey()
	if err != nil {
		return errors.Wrap(err, "failed to read host key")
	}

	serverConf := &ssh.ServerConfig{
		// OpenSSH-specific extensions compatibility
		ServerVersion:     "SSH-2.0-OpenSSH_Go_Bastion",
		PublicKeyCallback: s.authCallback,
	}
	serverConf.AddHostKey(hostKey)

	conn, chans, globalReqs, err := ssh.NewServerConn(nConn, serverConf)
	if err != nil {
		return errors.Wrap(err, "failed to handshake")
	}
	defer conn.Close()

	s.SugaredLogger = s.SugaredLogger.With(
		"sessid", conn.SessionID()[:6], // save some space in logs
	)
	s.username = conn.User()
	s.sessId = conn.SessionID()
	s.sshConn = conn
	s.Infow("authentication succeded", "user", conn.User())

	s.agent = &ClientAgent{
		SugaredLogger: s.SugaredLogger,
		sshConn:       conn,
	}
	s.clientProvider = client.NewProvider()

	errs := make(chan error)
	go s.handleChannels(chans, errs)
	go s.handleGlobalReqs(globalReqs)

	for err := range errs {
		if err != nil {
			s.Errorw("error in channel", "err", err)
			return err
		}
	}
	s.Info("connection closed")
	return nil
}
