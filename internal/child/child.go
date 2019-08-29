package child

import (
	"net"
	"os"

	"github.com/ilyaluk/bastion/internal/config"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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

	conf, err := config.Read(os.Args[1])
	if err != nil {
		return
	}
	log.Infow("loaded config", "conf", conf.Child)

	// create client connection from fd
	nConn, err := net.FileConn(os.NewFile(3, "nConn"))
	for err != nil {
		return errors.Wrap(err, "failed to create client conn")
	}
	defer nConn.Close()

	server := NewServer(conf.Child, log)
	if err = server.ProcessConnection(nConn); err != nil {
		log.Errorw("error while handling connection", "err", err)
		return
	}
	return
}
