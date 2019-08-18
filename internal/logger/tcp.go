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
}

type PcapWriter struct {
	*pcapgo.NgWriter
	Src     net.IP
	Dst     net.IP
	SrcPort uint16
	DstPort uint16
}

func (pw PcapWriter) Write(p []byte) (n int, err error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		// TODO: use SetNetworkLayerForChecksum
		// ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts,
		&layers.IPv4{
			Version:  4,
			SrcIP:    pw.Src,
			DstIP:    pw.Dst,
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			SrcPort: layers.TCPPort(pw.SrcPort),
			DstPort: layers.TCPPort(pw.DstPort),
		},
		gopacket.Payload(p),
	)
	if err != nil {
		return
	}

	ci := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(buf.Bytes()),
		Length:         len(buf.Bytes()),
		InterfaceIndex: 0,
	}
	err = pw.WritePacket(ci, buf.Bytes())
	if err != nil {
		return
	} else {
		return len(p), nil
	}
}

func (sl *TCPLogger) Start() (err error) {
	os.MkdirAll(sl.folder(), 0700)

	// TODO: check for name conflicts?
	fname := fmt.Sprintf("%s:%d-%s:%d-%v.pcapng", sl.Src, sl.SrcPort, sl.Dst, sl.DstPort, time.Now())
	f, err := os.Create(path.Join(sl.folder(), fname))
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

	// TODO: add tcp handshake and acks

	w1 := PcapWriter{
		NgWriter: w,
		Src:      sl.Src,
		Dst:      sl.Dst,
		SrcPort:  sl.SrcPort,
		DstPort:  sl.DstPort,
	}
	w2 := PcapWriter{
		NgWriter: w,
		Src:      sl.Dst,
		Dst:      sl.Src,
		SrcPort:  sl.DstPort,
		DstPort:  sl.SrcPort,
	}

	errs := make(chan error)
	sl.startLog(sl.ClientIn, sl.ServerIn, w1, errs)
	sl.startLog(sl.ServerOut, sl.ClientOut, w2, errs)

	// TODO: handle errors
	<-errs
	<-errs

	return nil
}
