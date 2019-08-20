package requests

import (
	"encoding/binary"
	"fmt"
)

// RFC 4254 Section 6.4
type SetenvRequest struct {
	Name  string
	Value string
}

// RFC 4254 Section 6.2
type PTYRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist []byte
}

// RFC 4254 Section 6.5
type SubsystemRequestMsg struct {
	Subsystem string
}

// RFC 4254 Section 6.5
type ExecMsg struct {
	Command string
}

// RFC 4254 Section 6.7
type PTYWindowChangeMsg struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

// RFC 4254 Section 6.9
type SignalMsg struct {
	Signal string
}

// RFC 4254 Section 6.10
type ExitStatusMsg struct {
	ExitStatus uint32
}

// RFC 4254 Section 6.10
type ExitSignalMsg struct {
	Signal     string
	CoreDumped bool
	Error      string
	Lang       string
}

// RFC 4254 Section 7.2
type ChannelOpenDirectMsg struct {
	RAddr string
	RPort uint32
	LAddr string
	LPort uint32
}

// RFC 4254 Section 8
func ParseModelist(data []byte) (res map[uint8]uint32, err error) {
	res = make(map[uint8]uint32)
	for len(data) > 0 {
		op := data[0]

		if len(data) == 1 && op == 0 {
			break
		}
		if len(data) < 5 {
			return res, fmt.Errorf("invalid rest data len %d, op %d", len(data), op)
		}

		if 160 <= op && op <= 255 {
			return res, fmt.Errorf("unexpected opcode %d", op)
		}
		arg := binary.BigEndian.Uint32(data[1:5])
		res[op] = arg

		data = data[5:]
	}
	return
}

type EOWMsg struct{}
