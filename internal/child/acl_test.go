package child

import (
	"testing"

	"github.com/ilyaluk/bastion/internal/config"
)

func Test_checkACL(t *testing.T) {
	type args struct {
		user string
		host string
		port uint16
		acls []config.DstACL
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"empty", args{"user", "host", 22, []config.DstACL{}}, false},
		{"allow for user", args{"user", "host", 22, []config.DstACL{{User: "user", Allow: true}}}, true},
		{"allow for host", args{"user", "host", 22, []config.DstACL{{Host: "host", Allow: true}}}, true},
		{"allow for port", args{"user", "host", 22, []config.DstACL{{Port: 22, Allow: true}}}, true},
		{"several cases", args{"user", "host", 22, []config.DstACL{
			{Port: 33, Allow: false},
			{Host: "host2", Allow: false},
			{User: "user2", Allow: false},
			{User: "user", Host: "host", Port: 22, Allow: true},
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkACL(tt.args.user, tt.args.host, tt.args.port, tt.args.acls); got != tt.want {
				t.Errorf("checkACL(%+v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
