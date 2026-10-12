//go:build !windows

package core

import (
	"context"
	"errors"
)

func BindInterface(string) (func(context.Context, int64) error, error) {
	return nil, errors.New("--bind-interface is a Windows CLI option; other hosts supply Hooks.Protect")
}
