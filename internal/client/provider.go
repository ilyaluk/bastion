package client

import (
	"sync"
)

type Host struct {
	user, host string
	port       uint16
}

type Provider struct {
	sync.RWMutex
	m map[Host]*Client
}

func NewProvider() *Provider {
	p := Provider{}
	p.m = make(map[Host]*Client)
	return &p
}

func (cp *Provider) get(key Host) (*Client, bool) {
	cp.RLock()
	c, ok := cp.m[key]
	cp.RUnlock()
	return c, ok
}

func (cp *Provider) store(key Host, val *Client) {
	cp.Lock()
	cp.m[key] = val
	cp.Unlock()
}

// GetClient get client from cache or creates new one with config
func (cp *Provider) GetClient(conf *Config) (*Client, error) {
	host := Host{conf.User, conf.Host, conf.Port}

	if c, ok := cp.get(host); ok {
		c.IncRefs()
		return c, nil
	}

	client, err := New(conf)
	if err != nil {
		return nil, err
	}
	cp.store(host, client)
	return client, nil
}
