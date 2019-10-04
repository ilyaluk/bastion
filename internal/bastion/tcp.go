package bastion

import (
	"fmt"
	"net"

	"github.com/ilyaluk/bastion/internal/logger"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type tcpConfig struct {
	newCh   ssh.NewChannel
	serv    *Server
	srcHost string
	srcPort uint16
	dstHost string
	dstPort uint16
}

func HandleTCP(tc *tcpConfig) {
	errs := tc.serv.errs
	log := tc.serv.SugaredLogger

	if tc.serv.client == nil {
		errs <- tc.newCh.Reject(ssh.ConnectionFailed, "have not connected to remote yet")
		return
	}

	// TODO: validate host
	dest := fmt.Sprintf("%s:%d", tc.dstHost, tc.dstPort)
	log.Info("dialing tcp", "dest", dest)
	conn, err := tc.serv.client.Dial("tcp", dest)
	if err != nil {
		// TODO: do not expose errors
		errs <- tc.newCh.Reject(ssh.ConnectionFailed, err.Error())
		errs <- err
		return
	}
	defer conn.Close()

	log.Info("accepting request")
	channel, reqs, err := tc.newCh.Accept()
	if err != nil {
		errs <- errors.Wrap(err, "failed to accept channel")
		return
	}
	log.Info("accepted tcp channel")

	// no requests here
	go ssh.DiscardRequests(reqs)

	defer channel.Close()

	tcpLog := logger.TCPLogger{
		Logger: logger.Logger{
			ClientIn:   channel,
			ClientOut:  channel,
			ServerIn:   conn,
			ServerOut:  conn,
			Username:   tc.serv.remoteUser,
			Hostname:   tc.dstHost,
			SessId:     tc.serv.sessId,
			RootFolder: tc.serv.Conf.LogFolder,
		},
		// TODO
		Src:     net.IP{127, 0, 0, 1},
		Dst:     net.IP{8, 8, 8, 8},
		SrcPort: tc.srcPort,
		DstPort: tc.dstPort,
	}
	if err = tcpLog.Start(); err != nil {
		log.Errorw("error while writing TCP log", "err", err)
	}
}
