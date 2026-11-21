package safe

import (
	"errors"
	"testing"
)

func TestCall(t *testing.T) {
	v, err := Call(func() (int, error) { return 1, nil })
	if v != 1 || err != nil {
		t.Fatal(v, err)
	}
	_, err = Call(func() (int, error) {
		panic("boom")
	})
	var pe *PanicError
	if !errors.As(err, &pe) || pe.Stack == "" || err.Error() != "panic: boom" {
		t.Fatalf("got %v", err)
	}
}
