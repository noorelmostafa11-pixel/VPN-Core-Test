package core

import "encoding/json"

func PublishReady(path string, value map[string]any) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return writeReady(path, b)
}
