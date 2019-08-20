package logger

import (
	"fmt"
	"net"
	"os"
	"path"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type TCPLogger struct {
	Logger
	Src     net.IP
	Dst     net.IP
	SrcPort uint16
	DstPort uint16
	SentSrc uint32
	SentDst uint32
}

type PcapWriter struct {
	*pcapgo.NgWriter
	Src     net.IP
	Dst     net.IP
	SrcPort uint16
	DstPort uint16
	SentSrc *uint32
	SentDst *uint32
}

func writePacket(pw *pcapgo.NgWriter, layers ...gopacket.SerializableLayer) (err error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(buf, opts, layers...)
	if err != nil {
		return
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(buf.Bytes()),
		Length:         len(buf.Bytes()),
		InterfaceIndex: 0,
	}
	return pw.WritePacket(ci, buf.Bytes())
}

func (pw PcapWriter) getIP(rev bool) *layers.IPv4 {
	src, dst := pw.Src, pw.Dst
	if rev {
		src, dst = dst, src
	}
	return &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    src,
		DstIP:    dst,
		Protocol: layers.IPProtocolTCP,
	}
}

func (pw PcapWriter) getTCP(rev, SYN, ACK, PSH bool, seq, ack uint32) *layers.TCP {
	src, dst := layers.TCPPort(pw.SrcPort), layers.TCPPort(pw.DstPort)
	if rev {
		src, dst = dst, src
	}
	return &layers.TCP{
		Window:  65535,
		SrcPort: src,
		DstPort: dst,
		SYN:     SYN,
		PSH:     PSH,
		ACK:     ACK,
		Seq:     seq,
		Ack:     ack,
	}
}

func (pw PcapWriter) Close() error {
	return pw.Flush()
}

func (pw PcapWriter) Write(p []byte) (n int, err error) {
	err = writePacket(pw.NgWriter,
		pw.getIP(false),
		pw.getTCP(false, false, true, true, *pw.SentSrc, *pw.SentDst),
		gopacket.Payload(p),
	)
	if err != nil {
		return
	}
	*pw.SentSrc += uint32(len(p))
	err = writePacket(pw.NgWriter,
		pw.getIP(true),
		pw.getTCP(true, false, true, false, *pw.SentDst, *pw.SentSrc),
	)
	if err != nil {
		return
	} else {
		return len(p), nil
	}
}

func writeHandshake(pw PcapWriter) (err error) {
	err = writePacket(pw.NgWriter,
		pw.getIP(false),
		pw.getTCP(false, true, false, false, 0, 0),
	)
	if err != nil {
		return
	}
	err = writePacket(pw.NgWriter,
		pw.getIP(true),
		pw.getTCP(true, true, true, false, 0, 1),
	)
	if err != nil {
		return
	}
	err = writePacket(pw.NgWriter,
		pw.getIP(false),
		pw.getTCP(false, false, true, false, 1, 1),
	)
	return
}

func (tl *TCPLogger) Start() (err error) {
	err = os.MkdirAll(tl.folder(), 0700)
	if err != nil {
		return
	}

	// TODO: check for name conflicts?
	ts := time.Now().Format("2006-01-02T15:04:05.999999")
	fname := fmt.Sprintf("%s:%d-%s:%d-%s.pcapng", tl.Src, tl.SrcPort, tl.Dst, tl.DstPort, ts)
	f, err := os.Create(path.Join(tl.folder(), fname))
	if err != nil {
		return
	}
	defer f.Close()

	// TODO: fill out more fields
	iface := pcapgo.NgInterface{
		Name:     "bastion capture",
		LinkType: layers.LinkTypeIPv4,
	}
	w, err := pcapgo.NewNgWriterInterface(f, iface, pcapgo.NgWriterOptions{})
	if err != nil {
		return
	}
	defer w.Flush()

	w1 := PcapWriter{
		NgWriter: w,
		Src:      tl.Src,
		Dst:      tl.Dst,
		SrcPort:  tl.SrcPort,
		DstPort:  tl.DstPort,
		SentSrc:  &tl.SentSrc,
		SentDst:  &tl.SentDst,
	}
	w2 := PcapWriter{
		NgWriter: w,
		Src:      tl.Dst,
		Dst:      tl.Src,
		SrcPort:  tl.DstPort,
		DstPort:  tl.SrcPort,
		SentSrc:  &tl.SentDst,
		SentDst:  &tl.SentSrc,
	}

	err = writeHandshake(w1)
	if err != nil {
		return
	}
	tl.SentSrc = 1
	tl.SentDst = 1

	errs := make(chan error)
	go tl.startLog(tl.ClientIn, tl.ServerIn, w1, errs)
	go tl.startLog(tl.ServerOut, tl.ClientOut, w2, errs)

	// TODO: handle errors
	<-errs
	<-errs

	return nil
}
