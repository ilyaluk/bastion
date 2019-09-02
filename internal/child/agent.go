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
	auth    ssh.AuthMethod
	refs    int32
}

func (ca *ClientAgent) Get() (am ssh.AuthMethod, err error) {
	newRefs := atomic.AddInt32(&ca.refs, 1)
	ca.Debugw("opening client agent", "newRefs", newRefs)

	if newRefs > 1 {
		return ca.auth, nil
	}

	ca.Debug("opening auth-agent channel")
	ch, reqs, err := ca.sshConn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return
	}
	ca.Debug("opened auth-agent channel")
	ca.ch = ch

	// no requests here whatsoever
	go ssh.DiscardRequests(reqs)

	ca.auth = ssh.PublicKeysCallback(agent.NewClient(ch).Signers)
	return ca.auth, nil
}

func (ca *ClientAgent) Close() {
	newRefs := atomic.AddInt32(&ca.refs, -1)
	ca.Debugw("closed client agent", "newRefs", newRefs)
	if newRefs == 0 {
		ca.ch.Close()
	}
}
