package bastion

type ACLValidator struct {
	ACLConfig
}

func NewACLValidator(conf ACLConfig) *ACLValidator {
	return &ACLValidator{ACLConfig: conf}
}

func checkACL(user, host string, port uint16, acls []DstACL) bool {
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
	return checkACL(user, host, port, v.Sessions)
}

func (v *ACLValidator) CheckForward(user, host string, port uint16) bool {
	return checkACL(user, host, port, v.Forwards)
}
