package core

import "errors"

type packetRejected struct{ error }

func isPacketRejected(err error) bool { var r packetRejected; return errors.As(err, &r) }
