package logger

import (
	"errors"
	"io"
)

type SessionLogger struct {
	Logger

	ClientErr io.Writer
	ServerErr io.Reader
	PTY       bool
	PTYCols   uint32
	PTYRows   uint32
	Command   string
}

func StartSessionLog(log SessionLogger, format string) error {
	switch format {
	case "sudoreplay":
		logger := SudoreplayLogger{SessionLogger: log}
		return logger.Start()
	case "asciicast":
		logger := AsciicastLogger{SessionLogger: log}
		return logger.Start()
	default:
		return errors.New("unknown session log format")
	}
}
