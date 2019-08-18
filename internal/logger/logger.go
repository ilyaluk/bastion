package logger

import (
	"encoding/base64"
	"io"
	"path"
	"strings"
)

type Logger struct {
	ClientIn  io.Reader
	ClientOut io.Writer
	ServerIn  io.Writer
	ServerOut io.Reader

	Username string
	Hostname string
	SessId   []byte

	RootFolder string
}

func (l *Logger) folder() string {
	sessId := base64.StdEncoding.EncodeToString(l.SessId)
	sessId = strings.Replace(sessId, "/", "_", -1)
	return path.Join(l.RootFolder, l.Username, l.Hostname, sessId)
}

func (l *Logger) startLog(r io.Reader, w io.Writer, log io.Writer, errs chan<- error) error {
	go func() {
		_, err := io.Copy(w, io.TeeReader(r, log))
		errs <- err
	}()
	return nil
}
