package child

import "github.com/ilyaluk/bastion/internal/config"

type ACLValidator struct {
	config.ACLConfig
}

func NewACLValidator(conf config.ACLConfig) *ACLValidator {
	return &ACLValidator{ACLConfig: conf}
}

func (v *ACLValidator) checkACL(user, host string, port uint16, acls []config.DstACL) bool {
	for _, acl := range acls {
		if (acl.User == "" || acl.User == user) &&
			(acl.Host == "" || acl.Host == host) &&
			(acl.Port == 0 || acl.Port == port) {
			return acl.Allow
		}
	}
	return false
}

func (v *ACLValidator) CheckSession(user, host string, port uint16) bool {
	return v.checkACL(user, host, port, v.Sessions)
}

func (v *ACLValidator) CheckForward(user, host string, port uint16) bool {
	return v.checkACL(user, host, port, v.Forwards)
}
