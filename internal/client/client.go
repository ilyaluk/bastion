package client

import (
	"fmt"
	"io"
	"time"

	"github.com/ilyaluk/bastion/internal/ssh_types"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	*zap.SugaredLogger
	User    string
	Host    string
	Port    uint16
	Auth    ssh.AuthMethod
	Timeout time.Duration
}

type Client struct {
	*Config
	*ssh.Client
}

type SessionConfig struct {
	PTYRequested bool
	PTYPayload   ssh_types.PTYRequestMsg
	Requests     chan interface{}
}

type Session struct {
	*ssh.Session

	Stdin  io.WriteCloser
	Stdout io.Reader
	Stderr io.Reader
}

func New(conf *Config) (c *Client, err error) {
	config := &ssh.ClientConfig{
		User:            conf.User,
		Auth:            []ssh.AuthMethod{conf.Auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO
		Timeout:         conf.Timeout,
		BannerCallback:  ssh.BannerDisplayStderr(),
		ClientVersion:   "SSH-2.0-OpenSSH_Go_Bastion",
	}

	c = &Client{
		Config: conf,
	}

	dst := fmt.Sprintf("%s:%d", conf.Host, conf.Port)
	c.Infow("connecting to remote", "dst", dst)
	client, err := ssh.Dial("tcp", dst, config)
	if err != nil {
		return
	}
	c.Debug("connected to remote")

	c.Client = client
	return
}

func (c *Client) NewSession(sc SessionConfig) (s *Session, err error) {
	sess, err := c.Client.NewSession()
	if err != nil {
		return
	}
	c.Debug("session allocated")

	if sc.PTYRequested {
		pty := sc.PTYPayload
		ml, err := ssh_types.ParseModelist(pty.Modelist)
		if err != nil {
			return nil, err
		}
		err = sess.RequestPty(pty.Term, int(pty.Rows), int(pty.Columns), ml)
		if err != nil {
			return nil, err
		}
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return nil, err
	}

	s = &Session{
		Session: sess,
		Stdin:   stdin,
		Stdout:  stdout,
		Stderr:  stderr,
	}
	go s.handleReqs(sc.Requests)
	return s, nil
}

func (s *Session) handleReqs(ch <-chan interface{}) {
	for r := range ch {
		switch req := r.(type) {
		case ssh_types.PTYWindowChangeMsg:
			_ = s.WindowChange(int(req.Rows), int(req.Columns))
		case ssh_types.SignalMsg:
			_ = s.Signal(ssh.Signal(req.Signal))
		case ssh_types.EOWMsg:
			_, _ = s.SendRequest("eow@openssh.com", false, nil)
		}
	}
}
