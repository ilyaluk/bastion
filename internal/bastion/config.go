package bastion

import (
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v2"
)

type DstACL struct {
	User  string
	Host  string
	Port  uint16
	Allow bool
}

type ACLConfig struct {
	Sessions []DstACL
	Forwards []DstACL
}

//noinspection GoStructTag
type Config struct {
	InetDStyle        bool          `yaml:"inetd_style"`
	HostKey           string        `yaml:"host_key"`
	ConnectTimeoutSec uint          `yaml:"connect_timeout"`
	ConnectTimeout    time.Duration `yaml:"-"`
	LogFormat         string        `yaml:"log_format"`
	LogFolder         string        `yaml:"log_folder"`
	CAKeys            string        `yaml:"ca_keys"`
	ACL               ACLConfig
}

func ReadConfig(fname string) (c Config, err error) {
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		return
	}

	if err = yaml.Unmarshal(data, &c); err != nil {
		return
	}
	c.ConnectTimeout = time.Second * time.Duration(c.ConnectTimeoutSec)
	return
}
