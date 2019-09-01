package client

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ilyaluk/bastion/internal/ssh_types"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	User    string
	Host    string
	Port    uint16
	Agent   ExtAgent
	Timeout time.Duration
	Log     *zap.SugaredLogger
}

type Client struct {
	*Config
	*zap.SugaredLogger
	*ssh.Client

	refs   int
	refsMu sync.Mutex
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

type ExtAgent interface {
	Get() (am ssh.AuthMethod, err error)
	Close()
}

func New(conf *Config) (c *Client, err error) {
	agent, err := conf.Agent.Get()
	if err != nil {
		return
	}

	config := &ssh.ClientConfig{
		User:            conf.User,
		Auth:            []ssh.AuthMethod{agent},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         conf.Timeout,
		BannerCallback:  ssh.BannerDisplayStderr(),
		ClientVersion:   "SSH-2.0-OpenSSH_Go_Bastion",
	}

	c = &Client{
		Config:        conf,
		SugaredLogger: conf.Log,
		refs:          1,
	}

	c.Info("connecting to remote")
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", conf.Host), config)
	if err != nil {
		return
	}
	c.Info("connected to remote, closing agent")
	conf.Agent.Close()

	c.Client = client
	return
}

func (c *Client) NewSession(sc SessionConfig) (s *Session, err error) {
	sess, err := c.Client.NewSession()
	if err != nil {
		return
	}
	c.Info("session allocated")

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

func (c *Client) IncRefs() {
	c.refsMu.Lock()
	defer c.refsMu.Unlock()

	c.refs++
}

func (c *Client) Close() {
	c.refsMu.Lock()
	defer c.refsMu.Unlock()

	c.refs--
	c.Infow("decreased refs on client agent", "refs", c.refs)
	if c.refs == 0 {
		c.Client.Close()
	}
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
