package conf_test

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

// Removing upstream's unreachable statements must not accidentally re-enable
// its rejected legacy reverse configuration or affect ordinary configurations.
func TestForkReverseGuardUnchanged(t *testing.T) {
	if _, err := (&conf.Config{}).Build(); err != nil {
		t.Fatal("ordinary configuration rejected:", err)
	}
	if _, err := (&conf.Config{Reverse: &conf.ReverseConfig{}}).Build(); err == nil || !strings.Contains(err.Error(), "legacy reverse") {
		t.Fatal("legacy reverse rejection changed:", err)
	}
}
