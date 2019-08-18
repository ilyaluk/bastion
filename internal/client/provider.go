package client

import (
	"sync"

	"github.com/pkg/errors"
)

type Host struct {
	user, host string
	port       uint16
}

type Provider struct {
	sync.Mutex
	m map[Host]*Client
}

func NewProvider() *Provider {
	p := Provider{}
	p.m = make(map[Host]*Client)
	return &p
}

// GetClient get client from cache or creates new one with config
func (cp *Provider) GetClient(conf *Config) (*Client, error) {
	cp.Lock()
	defer cp.Unlock()

	host := Host{conf.User, conf.Host, conf.Port}
	c, ok := cp.m[host]
	if ok {
		c.IncRefs()
		return c, nil
	}

	client, err := New(conf)
	if err != nil {
		return nil, errors.Wrap(err, "error creating new client")
	}
	cp.m[host] = client
	return client, nil
}
