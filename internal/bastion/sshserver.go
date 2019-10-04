package bastion

import (
	"fmt"
	"net"
	"os/user"
	"strconv"
	"strings"
	"sync"

	"github.com/ilyaluk/bastion/internal/client"
	"github.com/ilyaluk/bastion/internal/ssh_types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// Server implements SSH server that client connects to
type Server struct {
	Conf Config
	*zap.SugaredLogger
	acl *ACLValidator

	sshConn     *ssh.ServerConn
	sessId      []byte
	remoteUser  string
	remoteHost  string
	remotePort  uint16
	agent       *ClientAgent
	certChecker *ssh.CertChecker
	errs        chan error

	client         *client.Client
	noMoreSessions bool
}

func NewServer(conf Config, log *zap.SugaredLogger) *Server {
	return &Server{
		Conf:          conf,
		SugaredLogger: log,
		acl:           NewACLValidator(conf.ACL),
	}
}

func (s *Server) authCallback(sc ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	username := sc.User()
	username = strings.Split(username, "/")[0]
	meta := customSSHConnMetadata{
		ConnMetadata: sc,
		customUser:   username,
	}
	keyFp := ssh.FingerprintSHA256(pubKey)

	clientCert, ok := pubKey.(*ssh.Certificate)
	if s.certChecker != nil && ok {
		// client offered signed certificate and we have certChecker
		certFp := ssh.FingerprintSHA256(clientCert.SignatureKey)
		perms, err := s.certChecker.Authenticate(meta, pubKey)
		if err != nil {
			s.Infow("client offered invalid certificate",
				"err", err,
				"user", username,
				"pubkey-fp", keyFp,
				"ca-fp", certFp,
				"sessid", sc.SessionID(),
			)
			return nil, err
		}
		s.Infow("client offered valid certificate",
			"user", username,
			"pubkey-fp", keyFp,
			"ca-fp", certFp,
			"sessid", sc.SessionID(),
		)
		return perms, nil
	}

	usr, err := user.Lookup(username)
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
			"user", username,
			"pubkey-fp", keyFp,
			"sessid", sc.SessionID(),
		)
		return &ssh.Permissions{}, nil
	}
	s.Infow("client offered invalid key",
		"user", username,
		"pubkey-fp", keyFp,
		"sessid", sc.SessionID(),
	)
	return nil, fmt.Errorf("unknown public key for %q", sc.User())
}

func (s *Server) processClient(sshChans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	for {
		if sshChans == nil && reqs == nil {
			break
		}

		select {
		case ch, ok := <-sshChans:
			if !ok {
				sshChans = nil
				continue
			}
			s.Debugw("new channel request", "type", ch.ChannelType())
			switch ch.ChannelType() {
			case "session":
				if s.noMoreSessions {
					s.errs <- ch.Reject(ssh.Prohibited, "no-more-sessions was sent")
					continue
				}
				s.Infow("session request")

				go HandleSession(&sessionConfig{
					newCh: ch,
					serv:  s,
				})

			case "direct-tcpip", "direct-streamlocal@openssh.com":
				var tcpForwardReq ssh_types.ChannelOpenDirectMsg
				if ch.ChannelType() == "direct-streamlocal@openssh.com" {
					var udsForwardReq ssh_types.ChannelOpenDirectUDSMsg
					if err := ssh.Unmarshal(ch.ExtraData(), &udsForwardReq); err != nil {
						s.errs <- errors.Wrap(err, "error parsing uds request")
						continue
					}
					oldBastionPrefix := "/tmp/.fwd/localhost/"
					if strings.Index(udsForwardReq.RAddr, oldBastionPrefix) == 0 {
						tcpForwardReq.LAddr = udsForwardReq.LAddr
						tcpForwardReq.LPort = udsForwardReq.LPort
						tcpForwardReq.RAddr = "127.0.0.1"
						port, err := strconv.Atoi(udsForwardReq.RAddr[len(oldBastionPrefix):])
						if err != nil {
							s.errs <- ch.Reject(ssh.Prohibited, "invalid port in forward request")
							continue
						}
						tcpForwardReq.RPort = uint32(port)
					} else {
						s.errs <- ch.Reject(ssh.Prohibited, "UDS not yet supported")
						continue
					}
				} else {
					if err := ssh.Unmarshal(ch.ExtraData(), &tcpForwardReq); err != nil {
						s.errs <- errors.Wrap(err, "error parsing tcpip request")
						continue
					}
				}

				s.Infow("tcpip request", "req", tcpForwardReq)

				if s.client == nil && tcpForwardReq.LPort == 65535 && tcpForwardReq.LAddr == "127.0.0.1" {
					s.Info("OpenSSH connects with -J")
					innerServer := NewServer(s.Conf, s.SugaredLogger)
					innerServer.remoteHost = tcpForwardReq.RAddr
					innerServer.remotePort = uint16(tcpForwardReq.RPort)

					channel, reqs, err := ch.Accept()
					if err != nil {
						s.errs <- errors.Wrap(err, "failed to accept channel")
						return
					}
					s.Info("accepted stdio forward channel")

					// no requests here
					go ssh.DiscardRequests(reqs)
					if err = innerServer.ProcessConnection(fakeNetConn{channel}); err != nil {
						s.errs <- NewCritical(errors.Wrap(err, "failed process inner conn"))
					}
					return
				}

				if !s.acl.CheckForward(s.remoteUser, tcpForwardReq.RAddr, uint16(tcpForwardReq.RPort)) {
					s.Warnw("access denied")
					s.errs <- ch.Reject(ssh.Prohibited, "access denied")
					continue
				}

				go HandleTCP(&tcpConfig{
					newCh:   ch,
					serv:    s,
					srcHost: tcpForwardReq.LAddr,
					srcPort: uint16(tcpForwardReq.LPort),
					dstHost: tcpForwardReq.RAddr,
					dstPort: uint16(tcpForwardReq.RPort),
				})

			case "x11", "forwarded-tcpip", "tun@openssh.com", "forwarded-streamlocal@openssh.com":
				s.errs <- ch.Reject(ssh.Prohibited, fmt.Sprintf("using %s is prohibited", ch.ChannelType()))
			default:
				s.errs <- ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			}

		case req, ok := <-reqs:
			if !ok {
				reqs = nil
				continue
			}
			s.Debugw("global request", "req", req)
			switch req.Type {
			case "keepalive@openssh.com":
				s.errs <- req.Reply(true, nil)
			case "no-more-sessions@openssh.com":
				s.noMoreSessions = true
			default:
				// "[cancel-]tcpip-forward" falls here
				if req.WantReply {
					s.errs <- req.Reply(false, nil)
				}
			}
		}
	}

	close(s.errs)
}

func (s *Server) ProcessConnection(nConn net.Conn) (err error) {
	hostKey, err := readHostKey(s.Conf.HostKey)
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
	parts := strings.Split(conn.User(), "/")
	if len(parts) > 3 {
		return errors.New("invalid username provided, can be 'username[/remoteHost[/remotePort]]'")
	}

	s.remoteUser = parts[0]
	if len(parts) > 1 {
		s.remoteHost = parts[1]
	}
	if len(parts) > 2 {
		port, err := strconv.Atoi(parts[2])
		if err != nil {
			return fmt.Errorf("invalid remote port: %v", parts[2])
		}
		s.remotePort = uint16(port)
	} else if s.remotePort == 0 {
		s.remotePort = 22
	}

	s.sessId = conn.SessionID()
	s.sshConn = conn
	s.Infow("authentication succeded", "user", conn.User())

	s.agent = &ClientAgent{
		Mutex:         &sync.Mutex{},
		SugaredLogger: s.SugaredLogger,
		sshConn:       conn,
	}

	s.errs = make(chan error)
	go s.processClient(chans, globalReqs)

	for err := range s.errs {
		if err != nil {
			if _, ok := err.(CriticalError); ok {
				return errors.Wrap(err, "critical error in channel")
			}
			// TODO: write to client?
			s.Warnw("non-critical error in channel", "err", err)
		}
	}
	s.Info("connection closed")
	return nil
}
