package core

import (
	"errors"
	"strings"
)

func failurePhase(err error) string {
	var pe providerError
	if errors.As(err, &pe) && pe >= 300 && pe < 400 {
		return "TLS_FAILED"
	}
	s := reasonCode(err)
	if strings.HasPrefix(s, "BOOTSTRAP_DNS_") || s == "DNS_CALLBACK_BUSY" {
		return "DNS_FAILED"
	}
	if strings.HasPrefix(s, "TLS_") || strings.HasPrefix(s, "REALITY_") || strings.HasPrefix(s, "ECH_") {
		return "TLS_FAILED"
	}
	if strings.HasPrefix(s, "VLESS_") || strings.HasPrefix(s, "VMESS_") || strings.HasPrefix(s, "SS_") {
		return "PROTOCOL_FAILED"
	}
	return "TRANSPORT_FAILED"
}
