package bastiond

import (
	"io/ioutil"
	"net"
	"os"
	"os/exec"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v2"
)

type Config struct {
	ChildCmd   string   `yaml:"child_cmd"`
	ChildArgs  []string `yaml:"child_args"`
	ListenAddr string   `yaml:"listen_addr"`
}

type Server struct {
	Config
	*zap.SugaredLogger
}

func copyToFile(conn net.Conn) *os.File {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	file, err := tcpConn.File()
	if err != nil {
		return nil
	}
	return file
}

func (s *Server) handleConn(nConn net.Conn) {
	cmd := exec.Command(s.ChildCmd, s.ChildArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	file := copyToFile(nConn)
	nConn.Close()
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Start(); err != nil {
		s.Errorw("failed to start child", "err", err)
	}
	file.Close()
	if err := cmd.Wait(); err != nil {
		if eerr, ok := err.(*exec.ExitError); ok {
			s.Infow("child exited", "exitCode", eerr.ExitCode())
		} else {
			s.Errorw("error while running child", "err", err)
		}
	}
}

func (s *Server) start() (err error) {
	sock, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return
	}

	for {
		conn, err := sock.Accept()
		if err != nil {
			s.Errorw("failed to accept connection", "err", err)
		}
		defer conn.Close()

		s.Infow("new connection", "addr", conn.RemoteAddr())
		go s.handleConn(conn)
	}
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

	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		return
	}

	var conf Config
	if err = yaml.Unmarshal(data, &conf); err != nil {
		return
	}
	log.Infow("loaded config", "conf", conf)

	server := Server{
		Config:        conf,
		SugaredLogger: log,
	}
	return server.start()
}
