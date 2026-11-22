// Package safe runs code that parses outside data (sources, Helm charts) so
// a panic becomes an error. net/http recovers panics only in handlers; one
// in a goroutine of ours would kill the whole run.
package safe

import (
	"fmt"
	"runtime/debug"
)

// PanicError is a recovered panic, with the stack where it happened.
type PanicError struct {
	Value any
	Stack string
}

func (e *PanicError) Error() string { return fmt.Sprintf("panic: %v", e.Value) }

// Call returns fn's result, or a *PanicError if fn panics.
func Call[T any](fn func() (T, error)) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &PanicError{Value: r, Stack: string(debug.Stack())}
		}
	}()
	return fn()
}
