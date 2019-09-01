package child

import (
	"sync/atomic"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type ClientAgent struct {
	*zap.SugaredLogger
	sshConn *ssh.ServerConn
	ch      ssh.Channel
	refs    int32
}

func (ca *ClientAgent) Get() (am ssh.AuthMethod, err error) {
	atomic.AddInt32(&ca.refs, 1)

	ca.Info("opening auth-agent channel")
	ch, reqs, err := ca.sshConn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return
	}
	ca.Info("opened auth-agent channel")
	ca.ch = ch

	// no requests here whatsoever
	go ssh.DiscardRequests(reqs)

	am = ssh.PublicKeysCallback(agent.NewClient(ch).Signers)
	return
}

func (ca *ClientAgent) Close() {
	new := atomic.AddInt32(&ca.refs, -1)
	ca.Infow("decreased refs on client agent", "refs", new)
	if new == 0 {
		ca.ch.Close()
	}
}
