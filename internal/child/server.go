package child

import (
	"fmt"
	"io/ioutil"
	"net"
	"os/user"
	"strings"

	"github.com/ilyaluk/bastion/internal/client"
	"github.com/ilyaluk/bastion/internal/config"
	"github.com/ilyaluk/bastion/internal/ssh_types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// Server implements SSH server that client connects to
type Server struct {
	Conf config.Child
	*zap.SugaredLogger

	sshConn  *ssh.ServerConn
	sessId   []byte
	username string
	agent    *ClientAgent
	GlobalUserOptions
	clientProvider *client.Provider
	certChecker    *ssh.CertChecker
	acl            *ACLValidator
}

type GlobalUserOptions struct {
	envUsername    string
	lastRemote     string
	noMoreSessions bool
}

func NewServer(conf config.Child, log *zap.SugaredLogger) *Server {
	acl := NewACLValidator(conf.ACL)
	return &Server{Conf: conf, SugaredLogger: log, acl: acl}
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
	keyFp := ssh.FingerprintSHA256(pubKey)

	clientCert, ok := pubKey.(*ssh.Certificate)
	if s.certChecker != nil && ok {
		certFp := ssh.FingerprintSHA256(clientCert.SignatureKey)
		perms, err := s.certChecker.Authenticate(sc, pubKey)
		if err != nil {
			s.Infow("client offered invalid certificate",
				"err", err,
				"user", sc.User(),
				"pubkey-fp", keyFp,
				"ca-fp", certFp,
				"sessid", sc.SessionID(),
			)
			return nil, err
		}
		s.Infow("client offered valid certificate",
			"user", sc.User(),
			"pubkey-fp", keyFp,
			"ca-fp", certFp,
			"sessid", sc.SessionID(),
		)
		return perms, nil
	}

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

	if ak[string(pubKey.Marshal())] {
		s.Infow("client offered valid key",
			"user", sc.User(),
			"pubkey-fp", keyFp,
			"sessid", sc.SessionID(),
		)
		return &ssh.Permissions{}, nil
	}
	s.Infow("client offered invalid key",
		"user", sc.User(),
		"pubkey-fp", keyFp,
		"sessid", sc.SessionID(),
	)
	return nil, fmt.Errorf("unknown public key for %q", sc.User())
}

func (s *Server) handleClient(chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, errs chan<- error) {
	for {
		if chans == nil && reqs == nil {
			break
		}

		select {
		case ch, ok := <-chans:
			if !ok {
				chans = nil
				continue
			}
			s.Debugw("new channel request", "type", ch.ChannelType())
			switch ch.ChannelType() {
			case "session":
				if s.noMoreSessions {
					errs <- ch.Reject(ssh.Prohibited, "no-more-sessions was sent")
					continue
				}
				s.Infow("session request")

				go HandleSession(ch, &sessionConfig{
					channelConfig: channelConfig{
						SugaredLogger: s.SugaredLogger,
						conf:          s.Conf,
						errs:          errs,
						agent:         s.agent,
						username:      s.username,
						sessId:        s.sessId,
						clientProv:    s.clientProvider,
					},
					acl: s.acl,
				})

			case "direct-tcpip", "direct-streamlocal@openssh.com":
				var tcpForwardReq ssh_types.ChannelOpenDirectMsg
				if ch.ChannelType() == "direct-streamlocal@openssh.com" {
					var udsForwardReq ssh_types.ChannelOpenDirectUDSMsg
					if err := ssh.Unmarshal(ch.ExtraData(), &udsForwardReq); err != nil {
						errs <- errors.Wrap(err, "error parsing uds request")
						continue
					}
					if strings.Index(udsForwardReq.RAddr, "/tmp/.fwd/localhost/") == 0 {
						tcpForwardReq.LAddr = udsForwardReq.LAddr
						tcpForwardReq.LPort = udsForwardReq.LPort
					} else {
						errs <- ch.Reject(ssh.Prohibited, fmt.Sprintf("UDS not yet supported"))
						continue
					}
				} else {
					if err := ssh.Unmarshal(ch.ExtraData(), &tcpForwardReq); err != nil {
						errs <- errors.Wrap(err, "error parsing tcpip request")
						continue
					}
				}

				s.Infow("tcpip request", "req", tcpForwardReq)

				if !s.acl.CheckForward(s.username, tcpForwardReq.RAddr, uint16(tcpForwardReq.RPort)) {
					s.Warnw("access denied")
					errs <- ch.Reject(ssh.Prohibited, "access denied")
					continue
				}

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

			case "x11", "forwarded-tcpip", "tun@openssh.com", "forwarded-streamlocal@openssh.com":
				errs <- ch.Reject(ssh.Prohibited, fmt.Sprintf("using %s is prohibited", ch.ChannelType()))
			default:
				errs <- ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			}

		case req, ok := <-reqs:
			if !ok {
				reqs = nil
				continue
			}
			s.Debugw("global request", "req", req)
			switch req.Type {
			case "keepalive@openssh.com":
				errs <- req.Reply(true, nil)
			case "no-more-sessions@openssh.com":
				s.noMoreSessions = true
			default:
				// "[cancel-]tcpip-forward" falls here
				if req.WantReply {
					errs <- req.Reply(false, nil)
				}
			}
		}
	}

	close(errs)
}

func (s *Server) ProcessConnection(nConn net.Conn) (err error) {
	hostKey, err := s.readHostKey()
	if err != nil {
		return errors.Wrap(err, "failed to read host key")
	}

	if s.Conf.CAKeys != "" {
		caKeys, err := readAuthorizedKeys(s.Conf.CAKeys)
		if err != nil {
			return errors.Wrap(err, "failed to read CA keys")
		}
		s.certChecker = &ssh.CertChecker{
			// TODO: implement source-addr checks
			SupportedCriticalOptions: []string{},
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				_, ok := caKeys[string(auth.Marshal())]
				return ok
			},
		}
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
	go s.handleClient(chans, globalReqs, errs)

	for err := range errs {
		if err != nil {
			if _, ok := err.(CriticalError); ok {
				s.Errorw("critical error in channel", "err", err)
				return err
			}
			// TODO: write to client?
			s.Warnw("non-critical error in channel", "err", err)
		}
	}
	s.Info("connection closed")
	return nil
}
