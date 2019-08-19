package config

import (
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v2"
)

type Server struct {
	ChildCmd   string   `yaml:"child_cmd"`
	ChildArgs  []string `yaml:"child_args"`
	ListenAddr string   `yaml:"listen_addr"`
}

type Child struct {
	HostKey           string        `yaml:"host_key"`
	connectTimeoutInt uint          `yaml:"connect_timeout"`
	ConnectTimeout    time.Duration `yaml:"-"`
	LogFolder         string        `yaml:"log_folder"`
}

type Config struct {
	Server Server
	Child  Child
}

func Read(fname string) (c *Config, err error) {
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		return
	}

	c = new(Config)
	if err = yaml.Unmarshal(data, c); err != nil {
		return
	}
	c.Child.ConnectTimeout = time.Second * time.Duration(c.Child.connectTimeoutInt)
	return
}