package logger

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"time"
)

type SudoreplayLogger struct {
	SessionLogger
	timer *Timer
}

// type zlibWriteCloser struct {
// 	file io.WriteCloser
// 	comp io.WriteCloser
// }

// func newZlibWriteCloser(f io.WriteCloser) *zlibWriteCloser {
// 	return &zlibWriteCloser{
// 		file: f,
// 		comp: zlib.NewWriter(f),
// 	}
// }

// func (zwc zlibWriteCloser) Write(p []byte) (int, error) {
// 	fmt.Printf("%v %#v\n", zwc, p)
// 	return zwc.comp.Write(p)
// }

// func (zwc zlibWriteCloser) Close() error {
// 	// TODO: check err
// 	// TODO: panics here
// 	zwc.comp.Close()
// 	return zwc.file.Close()
// }

type writeDummyCloser struct {
	io.Writer
}

func (wdc writeDummyCloser) Close() error {
	return nil
}

type Timer struct {
	time.Time
	sync.Mutex
}

func (t *Timer) Init() {
	t.Time = time.Now()
}

func (t *Timer) GetDiff() time.Duration {
	t.Lock()
	defer t.Unlock()

	now := time.Now()
	diff := now.Sub(t.Time)
	t.Time = now
	return diff
}

type TimingWriter struct {
	log    io.WriteCloser
	timing io.WriteCloser
	id     int
	timer  *Timer
}

func (tw TimingWriter) Write(p []byte) (n int, err error) {
	n, err = tw.log.Write(p)
	if err != nil {
		return
	}
	secDiff := float64(tw.timer.GetDiff()) / float64(time.Second)
	te := fmt.Sprintf("%d %.6f %d\n", tw.id, secDiff, n)
	_, err = tw.timing.Write([]byte(te))
	return
}

func (tw TimingWriter) Close() error {
	// TODO
	tw.timing.Close()
	return tw.log.Close()
}

func (sl *SudoreplayLogger) createFiles() (res []io.WriteCloser, timing io.WriteCloser, err error) {
	timing, err = os.Create(path.Join(sl.folder(), "timing"))
	if err != nil {
		return
	}
	// timing = newZlibWriteCloser(timing)

	for id, fname := range []string{"stdin", "stdout", "stderr", "ttyin", "ttyout"} {
		log, err := os.Create(path.Join(sl.folder(), fname))
		if err != nil {
			return res, timing, err
		}

		tw := TimingWriter{
			log:    log, //newZlibWriteCloser(log),
			timing: timing,
			id:     id,
			timer:  sl.timer,
		}
		res = append(res, tw)
	}
	return
}

func (sl *SudoreplayLogger) Start() (err error) {
	sl.timer = &Timer{}
	sl.timer.Init()

	err = os.MkdirAll(sl.folder(), 0700)
	if err != nil {
		return
	}

	if sl.Command == "" {
		sl.Command = "/SHELL"
	}
	logData := fmt.Sprintf("%d:%s:::/dev/pts/0:%d:%d\n/\n%s",
		sl.timer.Time.Unix(), sl.Username, sl.PTYRows, sl.PTYCols, sl.Command)
	err = ioutil.WriteFile(path.Join(sl.folder(), "log"), []byte(logData), 0600)
	if err != nil {
		return
	}

	logs, timing, err := sl.createFiles()
	if err != nil {
		// TODO: close if partial success
		return
	}
	defer timing.Close()
	for _, log := range logs {
		defer log.Close()
	}

	errs := make(chan error)
	if !sl.PTY {
		go sl.startLog(sl.ClientIn, sl.ServerIn, logs[0], errs)
		go sl.startLog(sl.ServerOut, sl.ClientOut, logs[1], errs)
		// client stderr is extended channel and not needed to be closed
		go sl.startLog(sl.ServerErr, writeDummyCloser{sl.ClientErr}, logs[2], errs)
	} else {
		go sl.startLog(sl.ClientIn, sl.ServerIn, logs[3], errs)
		go sl.startLog(sl.ServerOut, sl.ClientOut, logs[4], errs)
	}

	// TODO: handle errors
	<-errs
	<-errs
	if !sl.PTY {
		<-errs
	}

	return nil
}
