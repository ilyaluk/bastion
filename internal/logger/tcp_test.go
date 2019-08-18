package logger

import (
	"io"
	"io/ioutil"
	"net"
	"testing"
	"time"
)

func TestTCPLogger(t *testing.T) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	l := TCPLogger{
		Logger: Logger{
			ClientIn:   r1,
			ClientOut:  ioutil.Discard,
			ServerIn:   ioutil.Discard,
			ServerOut:  r2,
			Username:   "test",
			Hostname:   "test",
			SessId:     []byte{0},
			RootFolder: "/tmp/logs",
		},
		Src:     net.IP{127, 0, 0, 1},
		Dst:     net.IP{8, 8, 8, 8},
		SrcPort: 1337,
		DstPort: 1338,
	}
	l.Start()

	w1.Write([]byte("test1"))
	w2.Write([]byte("test4"))

	w1.Close()
	w2.Close()
	time.Sleep(time.Second)
}
