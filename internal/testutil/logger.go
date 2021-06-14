package testutil

import (
	"sync"
	"testing"
)

// SafeTestLogger allows concurrent goroutines to safely log to a testing.T instance.
type SafeTestLogger struct {
	sync.Mutex
	testComplete bool
	t            *testing.T
}

// NewSafeLogger wraps the testing.T instance in a SafeTestLogger.
func NewSafeLogger(t *testing.T) *SafeTestLogger {
	l := &SafeTestLogger{t: t}
	t.Cleanup(func() {
		l.Lock()
		l.testComplete = true
		l.Unlock()
	})
	return l
}

// Logf safely logs to the wrapped testing.T instance.
func (l *SafeTestLogger) Logf(format string, a ...interface{}) {
	l.Lock()
	defer l.Unlock()
	if l.testComplete {
		return
	}
	l.t.Helper()
	l.t.Logf(format, a...)
}
