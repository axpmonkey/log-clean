package sanitize

import "fmt"

// ErrorKind classifies a Sanitize failure so the CLI can map it to the
// plan's distinct exit codes (2: input, 3: processing, 4: configuration).
type ErrorKind int

const (
	KindConfig ErrorKind = iota
	KindInput
	KindProcessing
)

// Error wraps a failure with the ErrorKind the CLI needs to pick an exit
// code, while still supporting errors.Is/As/Unwrap against the underlying error.
type Error struct {
	Kind ErrorKind
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func configErrorf(format string, args ...any) error {
	return &Error{Kind: KindConfig, Err: fmt.Errorf(format, args...)}
}

func inputErrorf(format string, args ...any) error {
	return &Error{Kind: KindInput, Err: fmt.Errorf(format, args...)}
}

func processingErrorf(format string, args ...any) error {
	return &Error{Kind: KindProcessing, Err: fmt.Errorf(format, args...)}
}
