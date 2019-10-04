package bastion

import (
	"sync"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type ClientAgent struct {
	*sync.Mutex
	*zap.SugaredLogger
	sshConn *ssh.ServerConn

	ch *ssh.Channel
}

func (ca *ClientAgent) GetAuth() (am ssh.AuthMethod, err error) {
	ca.Lock()
	defer ca.Unlock()

	if ca.ch == nil {
		ca.Debug("opening auth-agent channel")
		ch, reqs, err := ca.sshConn.OpenChannel("auth-agent@openssh.com", nil)
		if err != nil {
			return nil, err
		}
		ca.Debug("opened auth-agent channel")
		ca.ch = &ch

		// no requests here whatsoever
		go ssh.DiscardRequests(reqs)
	}

	return ssh.PublicKeysCallback(agent.NewClient(*ca.ch).Signers), nil
}

func (ca *ClientAgent) Close() error {
	ca.Lock()
	defer ca.Unlock()

	defer func() {
		ca.ch = nil
	}()
	return (*ca.ch).Close()
}
