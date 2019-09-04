package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type AsciicastLogger struct {
	SessionLogger
}

// func (tw TimingWriter) Write(p []byte) (n int, err error) {
// 	n, err = tw.log.Write(p)
// 	if err != nil {
// 		return
// 	}
// 	secDiff := float64(tw.timer.GetDiff()) / float64(time.Second)
// 	te := fmt.Sprintf("%d %.6f %d\n", tw.id, secDiff, n)
// 	_, err = tw.timing.Write([]byte(te))
// 	return
// }

type asciicastHeader struct {
	Version   int               `json:"version"`
	Width     uint32            `json:"width"`
	Height    uint32            `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Command   string            `json:"command,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

type asciicastEvent [3]interface{}

type asciicastWriter struct {
	Log   *json.Encoder
	Type  string
	Start time.Time
}

func (w asciicastWriter) Write(p []byte) (n int, err error) {
	now := time.Now()
	secDiff := float32(now.Sub(w.Start)) / float32(time.Second)
	data := asciicastEvent{
		secDiff,
		w.Type,
		string(p),
	}
	return len(p), w.Log.Encode(data)
}

func (w asciicastWriter) Close() error {
	return nil
}

func (l *AsciicastLogger) Start() (err error) {
	now := time.Now()

	dir, _ := filepath.Split(l.folder())
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return
	}

	f, err := os.Create(l.folder())
	if err != nil {
		return
	}
	defer f.Close()

	meta := asciicastHeader{
		Version:   2,
		Width:     l.PTYCols,
		Height:    l.PTYRows,
		Timestamp: now.Unix(),
		Command:   l.Command,
		Env:       nil,
	}
	encoder := json.NewEncoder(f)
	err = encoder.Encode(meta)
	if err != nil {
		return err
	}

	errs := make(chan error)
	go l.startLog(l.ClientIn, l.ServerIn, asciicastWriter{encoder, "i", now}, errs)
	go l.startLog(l.ServerOut, l.ClientOut, asciicastWriter{encoder, "o", now}, errs)
	if !l.PTY {
		// client stderr is extended channel and not needed to be closed
		go l.startLog(l.ServerErr, writeDummyCloser{l.ClientErr}, asciicastWriter{encoder, "o", now}, errs)
	}

	// TODO: handle errors
	<-errs
	<-errs
	if !l.PTY {
		<-errs
	}

	return nil
}
