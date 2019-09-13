package bastion

import (
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type nilTCPAddr string

func (n nilTCPAddr) Network() string {
	return "tcp"
}

func (n nilTCPAddr) String() string {
	return string(n)
}

type stdioNetConn struct{}

func (s stdioNetConn) Read(b []byte) (n int, err error) {
	return os.Stdin.Read(b)
}

func (s stdioNetConn) Write(b []byte) (n int, err error) {
	return os.Stdout.Write(b)
}

func (s stdioNetConn) Close() error {
	err1 := os.Stdin.Close()
	err2 := os.Stdout.Close()
	if err1 != nil || err2 != nil {
		return errors.Errorf("error closing in: %v, out: %", err1, err2)
	}
	return nil
}

func (s stdioNetConn) LocalAddr() net.Addr {
	return nilTCPAddr("stdin")
}

func (s stdioNetConn) RemoteAddr() net.Addr {
	return nilTCPAddr("stdout")
}

func (s stdioNetConn) SetDeadline(t time.Time) error {
	return nil
}

func (s stdioNetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (s stdioNetConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func Run() (err error) {
	logconfig := zap.NewDevelopmentConfig()
	logconfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, err := logconfig.Build()
	if err != nil {
		return
	}
	defer logger.Sync()
	log := logger.Sugar()

	if len(os.Args) < 2 {
		log.Fatalf("usage: %s config.yaml", os.Args[0])
	}

	inetdStyle := false
	if len(os.Args) >= 3 && os.Args[2] == "-i" {
		inetdStyle = true
	}

	conf, err := ReadConfig(os.Args[1])
	if err != nil {
		return
	}
	log.Infow("loaded config", "conf", conf)

	var clientConn net.Conn
	if inetdStyle {
		clientConn = stdioNetConn{}
	} else {
		clientConn, err = net.FileConn(os.NewFile(3, "nConn"))
		for err != nil {
			return errors.Wrap(err, "failed to create client conn")
		}
		defer clientConn.Close()
	}

	server := NewServer(conf, log)
	if err = server.ProcessConnection(clientConn); err != nil {
		log.Errorw("error while handling connection", "err", err)
		return
	}
	return
}
