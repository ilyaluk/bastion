package bastion

import (
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

func readHostKey(path string) (sign ssh.Signer, err error) {
	privateBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	return ssh.ParsePrivateKey(privateBytes)
}

func readAuthorizedKeys(path string) (map[string]bool, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ak := map[string]bool{}
	for len(data) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, err
		}

		ak[string(pubKey.Marshal())] = true
		data = rest
	}

	return ak, nil
}

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
		return errors.Errorf("error closing in: %v, out: %v", err1, err2)
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

type channelWriteCloser struct {
	c ssh.Channel
}

func (wc channelWriteCloser) Write(p []byte) (int, error) {
	return wc.c.Write(p)
}

func (wc channelWriteCloser) Close() error {
	return wc.c.CloseWrite()
}

type customSSHConnMetadata struct {
	ssh.ConnMetadata
	customUser string
}

func (c customSSHConnMetadata) User() string {
	return c.customUser
}
