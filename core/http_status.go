package core

import "errors"

type httpStatusError struct {
	reason string
	status int
}

func (e httpStatusError) Error() string { return e.reason }
func dialFailure(id uint64, err error) Event {
	v := Event{Event: "failure", ConnectionID: id, ReasonCode: reasonCode(err), Phase: failurePhase(err)}
	var s httpStatusError
	if errors.As(err, &s) {
		v.HTTPStatus = s.status
	}
	var p providerError
	if errors.As(err, &p) {
		v.NativeStatus = uint32(p)
	}
	return v
}
