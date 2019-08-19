package child

import (
	"fmt"

	"github.com/ilyaluk/bastion/internal/client"
	"github.com/ilyaluk/bastion/internal/config"
	"github.com/ilyaluk/bastion/internal/logger"
	"github.com/ilyaluk/bastion/internal/requests"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type channelConfig struct {
	conf config.Child
	*zap.SugaredLogger
	username   string
	sessId     []byte
	agent      *ClientAgent
	errs       chan<- error
	clientProv *client.Provider
}
type sessionConfig channelConfig

type Session struct {
	*sessionConfig
	ssh.Channel
	reqs <-chan *ssh.Request

	env            map[string]string
	ptyRequested   bool
	ptyPayload     requests.PTYRequestMsg
	agentRequested bool
	started        bool

	client  *client.Client
	session *client.Session
}

const (
	NocauthUser = "NOCAUTH_USER"
	NocauthHost = "NOCAUTH_HOST"
)

func NewSession(ch ssh.NewChannel, sc *sessionConfig) (*Session, error) {
	channel, reqs, err := ch.Accept()
	if err != nil {
		return nil, err
	}
	sc.Info("accepted session channel")

	return &Session{
		sessionConfig: sc,
		Channel:       channel,
		reqs:          reqs,

		env: make(map[string]string),
	}, nil
}

func (s *Session) writeErrClose(msg string) {
	// TODO: errors, full write
	s.Channel.Write([]byte(msg + "\r\n"))
	s.Close()
}

func (s *Session) handleReqs(in <-chan *ssh.Request) {
	for req := range in {
		s.Infow("channel request", "req", req, "ch", s.Channel)

		// validate if .started state correct
		switch req.Type {
		case "pty-req", "env", "auth-agent-req@openssh.com", "shell", "exec", "subsystem":
			if s.started {
				s.Warn("already started for this request")
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
		case "window-change", "signal", "eow@openssh.com":
			if !s.started {
				s.Warn("not yet started for this request")
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
		}

		// validate if everything needed present
		switch req.Type {
		case "shell", "exec", "subsystem":
			_, haveHost := s.env[NocauthHost]
			if !haveHost {
				s.Warn("don't have host")
				if req.Type != "subsystem" {
					req.Reply(true, nil)
					msg := fmt.Sprintf("please specify host to connect to in %s environment variable", NocauthHost)
					s.writeErrClose(msg)
				} else {
					req.Reply(false, nil)
					continue
				}
			}
			// pretty useless, client will disconnect without -A
			if !s.agentRequested {
				s.Warn("don't have agent")
				if req.Type != "subsystem" {
					req.Reply(true, nil)
					s.writeErrClose("please enable agent forwarding")
				} else {
					req.Reply(false, nil)
					continue
				}

			}
		}

		// process request
		switch req.Type {
		case "pty-req":
			var tmp requests.PTYRequestMsg
			err := ssh.Unmarshal(req.Payload, &tmp)
			if err != nil {
				s.Errorw("error parsing pty req", "err", err)
				req.Reply(false, nil)
				continue
			}
			s.Infow("pty request", "pty", tmp)
			req.Reply(true, nil)
			s.ptyRequested = true
			s.ptyPayload = tmp

		case "env":
			var tmp requests.SetenvRequest
			err := ssh.Unmarshal(req.Payload, &tmp)
			if err != nil {
				s.Errorw("error parsing env req", "err", err)
				req.Reply(false, nil)
				continue
			}
			s.env[tmp.Name] = tmp.Value
			s.Infow("env request", "name", tmp.Name, "val", tmp.Value)
			req.Reply(true, nil)

		case "auth-agent-req@openssh.com":
			s.agentRequested = true
			// TODO: remove after golang.org/cl/190777
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "shell":
			req.Reply(true, nil)
			s.started = true
			go s.startShell()

		case "exec":
			var tmp requests.ExecMsg
			err := ssh.Unmarshal(req.Payload, &tmp)
			if err != nil {
				s.Errorw("error parsing exec req", "err", err)
				req.Reply(false, nil)
			} else {
				s.Infow("exec req", "cmd", tmp.Command)
				req.Reply(true, nil)
				s.started = true
				go s.startExec(tmp.Command)
			}

		case "subsystem":
			// TODO
			fallthrough

		case "window-change":
			var tmp requests.PTYWindowChangeMsg
			err := ssh.Unmarshal(req.Payload, &tmp)
			if err != nil {
				s.Errorw("error parsing window change req", "err", err)
			} else {
				s.Infow("window size changed", "req", tmp)
				s.windowChange(tmp.Rows, tmp.Columns)
			}

		case "signal":
			var tmp requests.SignalMsg
			err := ssh.Unmarshal(req.Payload, &tmp)
			if err != nil {
				s.Errorw("error parsing signal req", "err", err)
			} else {
				s.Infow("signal", "sig", tmp.Signal)
				// TODO: validate?
				s.sendSignal(tmp.Signal)
			}

		case "eow@openssh.com":
			s.session.SendRequest("eow@openssh.com", false, nil)

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}

	}
}

func (s *Session) Handle() {
	go s.handleReqs(s.reqs)
}

func (s *Session) startClientSession(cmd string) {
	var err error

	user := s.username
	if user_, ok := s.env[NocauthUser]; ok {
		user = user_
	}

	// TODO: validate host
	host := s.env[NocauthHost]

	c, err := s.clientProv.GetClient(&client.Config{
		User:    user,
		Host:    host,
		Port:    22,
		Agent:   s.agent,
		Timeout: s.conf.ConnectTimeout,
		Log:     s.SugaredLogger,
	})
	if err != nil {
		s.errs <- errors.Wrap(err, "failed to create client")
		return
	}
	s.client = c

	sess, err := c.NewSession(client.SessionConfig{
		PTYRequested: s.ptyRequested,
		PTYPayload:   s.ptyPayload,
	})
	s.session = sess

	log := logger.SessionLogger{
		Logger: logger.Logger{
			ClientIn:   s.Channel,
			ClientOut:  s.Channel,
			ServerIn:   sess.Stdin,
			ServerOut:  sess.Stdout,
			Username:   user,
			Hostname:   host,
			SessId:     s.sessId,
			RootFolder: s.conf.LogFolder,
		},
		ClientErr: s.Channel.Stderr(),
		ServerErr: sess.Stderr,
		PTY:       s.ptyRequested,
		PTYCols:   s.ptyPayload.Columns,
		PTYRows:   s.ptyPayload.Rows,
		Command:   cmd,
	}
	go log.Start()
}

func (s *Session) doExec(cmd string) {
	s.startClientSession(cmd)
	defer s.session.Close()
	defer s.client.Close()
	defer s.Close()

	runner := s.session.Shell
	if cmd != "" {
		runner = func() error {
			return s.session.Run(cmd)
		}
	} else {
		cmd = "SHELL"
	}
	s.Infow("spawning process", "cmd", cmd)

	if err := runner(); err != nil {
		s.errs <- errors.Wrap(err, "error running process")
		return
	}
	s.Infow("process spawned", "cmd", cmd)
	err := s.session.Wait()
	s.Infow("process exited", "cmd", cmd, "err", err)

	var exitStatus requests.ExitStatusMsg
	if err == nil {
		s.SendRequest("exit-status", false, ssh.Marshal(exitStatus))
	} else if _, ok := err.(*ssh.ExitMissingError); ok {
		// ¯\_(ツ)_/¯
	} else if eerr, ok := err.(*ssh.ExitError); ok {
		exitStatus.ExitStatus = uint32(eerr.ExitStatus())
		s.SendRequest("exit-status", false, ssh.Marshal(exitStatus))

		if eerr.Signal() != "" {
			var exitSignal requests.ExitSignalMsg
			exitSignal.Error = eerr.Msg()
			exitSignal.Signal = eerr.Signal()
			exitSignal.Lang = eerr.Lang()
			s.SendRequest("exit-signal", false, ssh.Marshal(exitSignal))
		}
	}
}

func (s *Session) startShell() {
	s.doExec("")
}

func (s *Session) startExec(cmd string) {
	s.doExec(cmd)
}

func (s *Session) sendSignal(sig string) error {
	// TODO: wait for it
	if s.session == nil {
		return errors.New("session is not ready yet")
	}
	return s.session.Signal(ssh.Signal(sig))
}

func (s *Session) windowChange(h, w uint32) error {
	// TODO: wait for it
	if s.session == nil {
		return errors.New("session is not ready yet")
	}
	return s.session.WindowChange(int(h), int(w))
}

func (s *Session) requestPty(pty requests.PTYRequestMsg) error {
	modes, err := requests.ParseModelist(pty.Modelist)
	s.Infow("requesting pty", "pty", pty, "modes", modes)
	if err != nil {
		return err
	}
	return s.session.RequestPty(pty.Term, int(pty.Rows), int(pty.Columns), modes)
}
