package child

import (
	"fmt"
	"strconv"

	"github.com/ilyaluk/bastion/internal/client"
	"github.com/ilyaluk/bastion/internal/config"
	"github.com/ilyaluk/bastion/internal/logger"
	"github.com/ilyaluk/bastion/internal/ssh_types"
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

type sessionConfig struct {
	channelConfig
	acl *ACLValidator
}

type clientOptions struct {
	env            map[string]string
	ptyRequested   bool
	ptyPayload     ssh_types.PTYRequestMsg
	agentRequested bool
	// following is set via env vars
	envHost string
	envUser string
	envPort uint16
}

type Session struct {
	*sessionConfig
	ssh.Channel
	reqs       <-chan *ssh.Request
	clientReqs chan interface{}
	started    bool
	clientOptions

	client  *client.Client
	session *client.Session
	log     logger.SessionLogger
}

const (
	NocauthUser = "NOCAUTH_USER"
	NocauthHost = "NOCAUTH_HOST"
	NocauthPort = "NOCAUTH_PORT"
)

type channelWriteCloser struct {
	c ssh.Channel
}

func (wc channelWriteCloser) Write(p []byte) (int, error) {
	return wc.c.Write(p)
}

func (wc channelWriteCloser) Close() error {
	return wc.c.CloseWrite()
}

func HandleSession(ch ssh.NewChannel, sc *sessionConfig) {
	channel, reqs, err := ch.Accept()
	if err != nil {
		sc.errs <- err
		return
	}
	sc.Info("accepted session channel")

	s := Session{
		sessionConfig: sc,
		Channel:       channel,
		reqs:          reqs,
		clientReqs:    make(chan interface{}),
		clientOptions: clientOptions{
			env:     make(map[string]string),
			envPort: 22,
			envUser: sc.username,
		},
	}

	s.handleReqs(s.reqs)
}

func (s *Session) writeErrClose(msg string) {
	// TODO: errors, full write
	s.Write([]byte(msg + "\r\n"))
	s.SendRequest("exit-status", false, ssh.Marshal(ssh_types.ExitStatusMsg{1}))
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

		rejectRequest := func(req *ssh.Request, reason string) error {
			if req.Type != "subsystem" {
				err := req.Reply(true, nil)
				if err != nil {
					return err
				}
				s.writeErrClose(reason)
			} else {
				return req.Reply(false, nil)
			}
			return nil
		}

		// validate if everything needed present and ACL
		switch req.Type {
		case "shell", "exec", "subsystem":
			if s.envHost == "" {
				s.Warn("don't have host")
				msg := fmt.Sprintf("please specify host to connect to in %s environment variable", NocauthHost)
				rejectRequest(req, msg)
			}
			// pretty useless, client will disconnect without -A
			if !s.agentRequested {
				s.Warn("don't have agent")
				rejectRequest(req, "please enable agent forwarding")
			}
			if !s.acl.CheckSession(s.envUser, s.envHost, s.envPort) {
				s.Warn("access denied")
				rejectRequest(req, "access denied")
			}
		}

		// process request
		switch req.Type {
		case "pty-req":
			var tmp ssh_types.PTYRequestMsg
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
			var tmp ssh_types.SetenvRequest
			err := ssh.Unmarshal(req.Payload, &tmp)
			if err != nil {
				s.Errorw("error parsing env req", "err", err)
				req.Reply(false, nil)
				continue
			}
			s.Infow("env request", "name", tmp.Name, "val", tmp.Value)
			switch tmp.Name {
			case NocauthHost:
				s.envHost = tmp.Value
			case NocauthUser:
				s.envUser = tmp.Value
			case NocauthPort:
				port, err := strconv.Atoi(tmp.Value)
				if err != nil {
					s.Errorw("invalid port sent", "err", err)
					req.Reply(false, nil)
					continue
				}
				s.envPort = uint16(port)
			default:
				s.env[tmp.Name] = tmp.Value
			}
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
			go s.doExec("")

		case "exec":
			var tmp ssh_types.ExecMsg
			err := ssh.Unmarshal(req.Payload, &tmp)
			if err != nil {
				s.Errorw("error parsing exec req", "err", err)
				req.Reply(false, nil)
			} else {
				s.Infow("exec req", "cmd", tmp.Command)
				req.Reply(true, nil)
				s.started = true
				go s.doExec(tmp.Command)
			}

		case "subsystem":
			// TODO
			fallthrough

		case "window-change":
			var changeMsg ssh_types.PTYWindowChangeMsg
			err := ssh.Unmarshal(req.Payload, &changeMsg)
			if err != nil {
				s.Errorw("error parsing window change req", "err", err)
			} else {
				s.Infow("window size changed", "req", changeMsg)
				s.clientReqs <- changeMsg
			}

		case "signal":
			var sigMsg ssh_types.SignalMsg
			err := ssh.Unmarshal(req.Payload, &sigMsg)
			if err != nil {
				s.Errorw("error parsing signal req", "err", err)
			} else {
				s.Infow("signal", "sig", sigMsg.Signal)
				// TODO: validate signals?
				s.clientReqs <- sigMsg
			}

		case "eow@openssh.com":
			s.clientReqs <- ssh_types.EOWMsg{}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}

	}
}

func (s *Session) startClientSession(cmd string) error {
	var err error

	// TODO: validate host
	host := s.envHost
	user := s.envUser
	port := s.envPort

	s.Info("getting client")
	c, err := s.clientProv.GetClient(&client.Config{
		User:    user,
		Host:    host,
		Port:    port,
		Agent:   s.agent,
		Timeout: s.conf.ConnectTimeout,
		Log:     s.SugaredLogger,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create client")
	}
	s.client = c

	s.Info("creating session")
	sess, err := c.NewSession(client.SessionConfig{
		PTYRequested: s.ptyRequested,
		PTYPayload:   s.ptyPayload,
		Requests:     s.clientReqs,
	})
	if err != nil {
		return errors.Wrap(err, "failed to allocate session")
	}
	s.session = sess

	s.Info("creating logger")
	s.log = logger.SessionLogger{
		Logger: logger.Logger{
			ClientIn:   s.Channel,
			ClientOut:  channelWriteCloser{s.Channel},
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
	return nil
}

func (s *Session) doExec(cmd string) {
	err := s.startClientSession(cmd)
	if err != nil {
		// TODO: maybe do not expose full errors
		s.writeErrClose(err.Error())
		s.errs <- err
		return
	}
	defer s.Close()
	defer s.client.Close()
	defer s.session.Close()

	go func() {
		err := logger.StartSessionLog(s.log, s.conf.LogFormat)
		if err != nil {
			s.Errorw("session logger returned", "err", err)
		} else {
			s.Info("session logger exited")
		}
		s.Close()
	}()

	runner := s.session.Shell
	if cmd != "" {
		runner = func() error {
			return s.session.Start(cmd)
		}
	} else {
		cmd = "SHELL"
	}
	s.Infow("spawning process", "cmd", cmd)

	if err := runner(); err != nil {
		// TODO: maybe do not expose full errors
		s.writeErrClose(err.Error())
		s.errs <- errors.Wrap(err, "error running process")
		return
	}
	s.Infow("process spawned", "cmd", cmd)
	err = s.session.Wait()
	s.Infow("process exited", "cmd", cmd, "err", err)

	var exitStatus ssh_types.ExitStatusMsg
	if err == nil {
		_, err := s.SendRequest("exit-status", false, ssh.Marshal(exitStatus))
		if err != nil {
			s.Errorw("error sending exit-status", "err", err)
		}
		s.Infow("sent exit 0")
	} else if _, ok := err.(*ssh.ExitMissingError); ok {
		// ¯\_(ツ)_/¯
		s.Warn("remote exited without status or signal")
	} else if eerr, ok := err.(*ssh.ExitError); ok {
		exitStatus.ExitStatus = uint32(eerr.ExitStatus())
		_, err := s.SendRequest("exit-status", false, ssh.Marshal(exitStatus))
		if err != nil {
			s.Errorw("error sending exit-status", "err", err)
		}

		if eerr.Signal() != "" {
			var exitSignal ssh_types.ExitSignalMsg
			exitSignal.Error = eerr.Msg()
			exitSignal.Signal = eerr.Signal()
			exitSignal.Lang = eerr.Lang()
			_, err := s.SendRequest("exit-signal", false, ssh.Marshal(exitSignal))
			if err != nil {
				s.Errorw("error sending exit-signal", "err", err)
			}
		}
	}
}
