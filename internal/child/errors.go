package child

// TODO: check if this is needed
// CriticalError represents critical bastion child error
type CriticalError struct {
	// Err stores actual error
	Err error
}

// NewCriticalError returns new critical error
func NewCritical(err error) CriticalError {
	return CriticalError{Err: err}
}

// Error implements error interface
func (e CriticalError) Error() string {
	return e.Err.Error()
}
