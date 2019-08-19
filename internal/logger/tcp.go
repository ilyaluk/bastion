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

func (pw PcapWriter) Close() error {
	return pw.Flush()
}

func (pw PcapWriter) Write(p []byte) (n int, err error) {
	// TODO: refactor packet writingf
	err = writePacket(pw.NgWriter,
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    pw.Src,
			DstIP:    pw.Dst,
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			Window:  65535,
			SrcPort: layers.TCPPort(pw.SrcPort),
			DstPort: layers.TCPPort(pw.DstPort),
			PSH:     true,
			ACK:     true,
			Seq:     *pw.SentSrc,
			Ack:     *pw.SentDst,
		},
		gopacket.Payload(p),
	)
	if err != nil {
		return
	}
	*pw.SentSrc += uint32(len(p))
	err = writePacket(pw.NgWriter,
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    pw.Dst,
			DstIP:    pw.Src,
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			Window:  65535,
			SrcPort: layers.TCPPort(pw.DstPort),
			DstPort: layers.TCPPort(pw.SrcPort),
			ACK:     true,
			Seq:     *pw.SentDst,
			Ack:     *pw.SentSrc,
		},
	)
	if err != nil {
		return
	} else {
		return len(p), nil
	}
}

func writeHandshake(pw PcapWriter) (err error) {
	err = writePacket(pw.NgWriter,
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    pw.Src,
			DstIP:    pw.Dst,
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			Window:  65535,
			SrcPort: layers.TCPPort(pw.SrcPort),
			DstPort: layers.TCPPort(pw.DstPort),
			SYN:     true,
			Seq:     0,
			Ack:     0,
		},
	)
	if err != nil {
		return
	}
	err = writePacket(pw.NgWriter,
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    pw.Dst,
			DstIP:    pw.Src,
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			Window:  65535,
			SrcPort: layers.TCPPort(pw.DstPort),
			DstPort: layers.TCPPort(pw.SrcPort),
			SYN:     true,
			ACK:     true,
			Seq:     0,
			Ack:     1,
		},
	)
	if err != nil {
		return
	}
	err = writePacket(pw.NgWriter,
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    pw.Src,
			DstIP:    pw.Dst,
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			Window:  65535,
			SrcPort: layers.TCPPort(pw.SrcPort),
			DstPort: layers.TCPPort(pw.DstPort),
			ACK:     true,
			Seq:     1,
			Ack:     1,
		},
	)
	return
}

func (tl *TCPLogger) Start() (err error) {
	os.MkdirAll(tl.folder(), 0700)

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

	writeHandshake(w1)
	tl.SentSrc = 1
	tl.SentDst = 1

	errs := make(chan error)
	tl.startLog(tl.ClientIn, tl.ServerIn, w1, errs)
	tl.startLog(tl.ServerOut, tl.ClientOut, w2, errs)

	// TODO: handle errors
	<-errs
	<-errs

	return nil
}
