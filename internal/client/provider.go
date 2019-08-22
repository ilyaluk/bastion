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
	host := Host{conf.User, conf.Host, conf.Port}

	cp.Lock()
	c, ok := cp.m[host]
	cp.Unlock()
	if ok {
		c.IncRefs()
		return c, nil
	}

	// Slow operation, ssh dialing and stuff, hence unlock before
	client, err := New(conf)
	if err != nil {
		return nil, errors.Wrap(err, "error creating new client")
	}
	cp.Lock()
	cp.m[host] = client
	cp.Unlock()
	return client, nil
}
