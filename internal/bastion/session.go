package bastion

import (
	"fmt"
	"strconv"

	"github.com/ilyaluk/bastion/internal/client"
	"github.com/ilyaluk/bastion/internal/logger"
	"github.com/ilyaluk/bastion/internal/ssh_types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type channelConfig struct {
	conf Config
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

type sessionUserOptions struct {
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
	GlobalUserOptions
	sessionUserOptions

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

	s := Session{
		sessionConfig: sc,
		Channel:       channel,
		reqs:          reqs,
		clientReqs:    make(chan interface{}),
		sessionUserOptions: sessionUserOptions{
			env:     make(map[string]string),
			envPort: 22,
			envUser: sc.username,
		},
	}

	s.handleReqs(s.reqs)
}

func (s *Session) writeInfo(msg string, args ...interface{}) error {
	data := fmt.Sprintf(msg, args...)
	_, err := s.Write([]byte(data + "\r\n"))
	return err
}

func (s *Session) writeErrClose(msg string, args ...interface{}) error {
	err := s.writeInfo(msg, args...)
	if err != nil {
		return err
	}
	_, err = s.SendRequest("exit-status", false, ssh.Marshal(ssh_types.ExitStatusMsg{1}))
	if err != nil {
		return err
	}
	return s.Close()
}

func (s *Session) handleReqs(in <-chan *ssh.Request) {
	for req := range in {
		s.Debugw("channel request", "req", req, "ch", s.Channel)

		// validate if .started state correct
		switch req.Type {
		case "pty-req", "env", "auth-agent-req@openssh.com", "shell", "exec", "subsystem":
			if s.started {
				if req.WantReply {
					s.errs <- req.Reply(false, []byte("already started for this request"))
				}
				continue
			}
		case "window-change", "signal", "eow@openssh.com":
			if !s.started {
				if req.WantReply {
					s.errs <- req.Reply(false, []byte("not yes started for this request"))
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
				return s.writeErrClose(reason)
			}
			return req.Reply(false, nil)
		}

		// validate if everything needed present and ACL
		switch req.Type {
		case "shell", "exec", "subsystem":
			if s.envHost == "" {
				s.Debug("user haven't specified host")
				msg := fmt.Sprintf("error: no host specified (set it in %s env var)", NocauthHost)
				s.errs <- rejectRequest(req, msg)
				continue
			}
			if !s.agentRequested {
				s.Debug("user haven't provided agent")
				s.errs <- rejectRequest(req, "error: agent forwarding disabled (enable it with -A)")
				continue
			}
			if !s.acl.CheckSession(s.envUser, s.envHost, s.envPort) {
				s.Info("access denied", "user", s.envUser, "host", s.envHost, "port", s.envPort)
				s.errs <- rejectRequest(req, "error: access denied")
				continue
			}
		}

		// process request
		switch req.Type {
		case "pty-req":
			var tmp ssh_types.PTYRequestMsg
			err := ssh.Unmarshal(req.Payload, &tmp)
			if err != nil {
				s.errs <- req.Reply(false, nil)
				s.errs <- err
				continue
			}
			s.Debugw("pty request", "pty", tmp)
			s.errs <- req.Reply(true, nil)
			s.ptyRequested = true
			s.ptyPayload = tmp

		case "env":
			var tmp ssh_types.SetenvRequest
			err := ssh.Unmarshal(req.Payload, &tmp)
			if err != nil {
				s.errs <- err
				continue
			}
			// TODO: remove after golang.org/cl/190777
			if req.WantReply {
				s.errs <- req.Reply(true, nil)
			}
			s.Debugw("env request", "name", tmp.Name, "val", tmp.Value)
			switch tmp.Name {
			case NocauthHost:
				s.envHost = tmp.Value
			case NocauthUser:
				s.envUser = tmp.Value
			case NocauthPort:
				port, err := strconv.Atoi(tmp.Value)
				if err != nil {
					s.errs <- s.writeInfo("warning: invalid %s value", NocauthPort)
					continue
				}
				s.envPort = uint16(port)
			default:
				s.env[tmp.Name] = tmp.Value
			}

		case "auth-agent-req@openssh.com":
			s.agentRequested = true
			// TODO: remove after golang.org/cl/190777
			if req.WantReply {
				s.errs <- req.Reply(true, nil)
			}

		case "shell":
			s.errs <- req.Reply(true, nil)
			s.started = true
			go s.doExec("")

		case "exec":
			var tmp ssh_types.ExecMsg
			err := ssh.Unmarshal(req.Payload, &tmp)
			if err != nil {
				s.Errorw("error parsing exec req", "err", err)
				s.errs <- req.Reply(false, nil)
			} else {
				s.Infow("exec req", "cmd", tmp.Command)
				s.errs <- req.Reply(true, nil)
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
				// TODO: pass error
				s.Debugw("error parsing window change req", "err", err)
			} else {
				s.Debugw("window size changed", "req", changeMsg)
				s.clientReqs <- changeMsg
			}

		case "signal":
			var sigMsg ssh_types.SignalMsg
			err := ssh.Unmarshal(req.Payload, &sigMsg)
			if err != nil {
				s.Debugw("error parsing signal req", "err", err)
			} else {
				s.Debugw("signal", "sig", sigMsg.Signal)
				// TODO: validate signals?
				s.clientReqs <- sigMsg
			}

		case "eow@openssh.com":
			s.clientReqs <- ssh_types.EOWMsg{}

		default:
			s.Infow("unknown session request sent", "req", req)
			if req.WantReply {
				s.errs <- req.Reply(false, nil)
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

	s.Debug("getting client")
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

	s.Debug("opening session")
	sess, err := c.NewSession(client.SessionConfig{
		PTYRequested: s.ptyRequested,
		PTYPayload:   s.ptyPayload,
		Requests:     s.clientReqs,
	})
	if err != nil {
		return errors.Wrap(err, "failed to allocate session")
	}
	s.session = sess

	s.Debug("creating logger")
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
		s.errs <- s.writeErrClose(err.Error())
		s.errs <- err
		return
	}
	// close user connection
	defer s.Close()
	// decrease remote client refs
	defer s.client.Close()
	// close remote session
	defer s.session.Close()

	go func() {
		err := logger.StartSessionLog(s.log, s.conf.LogFormat)
		if err != nil {
			// TODO: pass return
			s.Infow("session logger returned", "err", err)
		} else {
			s.Debug("session logger exited")
		}
		s.Close()
	}()

	// kinda hacky generic way to spawn shell or command
	runner := s.session.Shell
	if cmd != "" {
		runner = func() error {
			return s.session.Start(cmd)
		}
	} else {
		// only for logs
		cmd = "SHELL"
	}
	s.Debugw("spawning process", "cmd", cmd)

	if err := runner(); err != nil {
		// TODO: maybe do not expose full errors
		s.errs <- s.writeErrClose(err.Error())
		s.errs <- errors.Wrap(err, "error running process")
		return
	}
	s.Debug("process spawned")
	err = s.session.Wait()
	s.Debugw("process exited", "err", err)

	var exitStatus ssh_types.ExitStatusMsg
	if err == nil {
		s.Debugw("sending exit 0")
		_, err := s.SendRequest("exit-status", false, ssh.Marshal(exitStatus))
		if err != nil {
			s.errs <- err
		}
	} else if _, ok := err.(*ssh.ExitMissingError); ok {
		// ¯\_(ツ)_/¯
		s.Debugw("remote exited without status or signal")
	} else if eerr, ok := err.(*ssh.ExitError); ok {
		exitStatus.ExitStatus = uint32(eerr.ExitStatus())
		s.Debugw("sending exit-status", "req", exitStatus)
		_, err := s.SendRequest("exit-status", false, ssh.Marshal(exitStatus))
		if err != nil {
			s.errs <- err
		}

		if eerr.Signal() != "" {
			var exitSignal ssh_types.ExitSignalMsg
			exitSignal.Error = eerr.Msg()
			exitSignal.Signal = eerr.Signal()
			exitSignal.Lang = eerr.Lang()
			s.Debugw("sending exit-signal", "req", exitSignal)
			_, err := s.SendRequest("exit-signal", false, ssh.Marshal(exitSignal))
			if err != nil {
				s.errs <- err
			}
		}
	}
}
