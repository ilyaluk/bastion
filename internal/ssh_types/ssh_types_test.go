package ssh_types

import (
	"reflect"
	"testing"
)

func TestParseModelist(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantRes map[uint8]uint32
		wantErr bool
	}{
		{"empty", []byte{}, map[uint8]uint32{}, false},
		{"sampleValid", []byte{1, 0, 0, 0, 123, 0}, map[uint8]uint32{1: 123}, false},
		{"reserved", []byte{160, 0, 0, 0, 123, 0}, map[uint8]uint32{}, true},
		{"leftovers", []byte{1, 1}, map[uint8]uint32{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRes, err := ParseModelist(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseModelist(%v) error = %v, wantErr %v", tt.data, err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRes, tt.wantRes) {
				t.Errorf("ParseModelist(%v) gotRes = %v, want %v", tt.data, gotRes, tt.wantRes)
			}
		})
	}
}
