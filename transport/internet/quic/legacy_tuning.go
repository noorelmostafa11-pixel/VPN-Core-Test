package quic

import (
	"errors"
	"time"

	q "github.com/apernet/quic-go"
	"github.com/xtls/xray-core/transport/internet"
)

// ValidateLegacyQUICParams admits only bounded, explicitly requested flow
// limits already understood by the bundled QUIC library. Legacy packet/header
// encryption, browser fingerprints and congestion control remain unchanged.
func ValidateLegacyQUICParams(p *internet.QuicParams) error {
	if p == nil {
		return nil
	}
	if p.Congestion != "" || p.BbrProfile != "" ||
		p.BrutalUp != 0 || p.BrutalDown != 0 || p.BrutalDisableLossCompensation ||
		p.DisablePathMtuDiscovery || p.DisableChromeParrot || p.DisableGSO || p.DisableStatelessReset {
		return errors.New("legacy QUIC: unsupported modern QUIC tuning")
	}
	if p.MaxIdleTimeout != 0 && (p.MaxIdleTimeout < 4 || p.MaxIdleTimeout > 120) {
		return errors.New("legacy QUIC: max idle timeout outside 4..120 seconds")
	}
	if p.KeepAlivePeriod != 0 && (p.KeepAlivePeriod < 2 || p.KeepAlivePeriod > 60) {
		return errors.New("legacy QUIC: keep-alive outside 2..60 seconds")
	}
	idle := p.MaxIdleTimeout
	if idle == 0 {
		idle = 60
	}
	if p.KeepAlivePeriod >= idle && p.KeepAlivePeriod != 0 {
		return errors.New("legacy QUIC: keep-alive must be shorter than idle timeout")
	}
	if p.MaxIncomingStreams != 0 && (p.MaxIncomingStreams < 8 || p.MaxIncomingStreams > 128) {
		return errors.New("legacy QUIC: incoming streams outside 8..128")
	}
	const maxWindow = 16 * 1024 * 1024
	for _, window := range []struct{ initial, max uint64 }{
		{p.InitStreamReceiveWindow, p.MaxStreamReceiveWindow},
		{p.InitConnReceiveWindow, p.MaxConnReceiveWindow},
	} {
		if window.initial == 0 && window.max == 0 {
			continue
		}
		if window.initial < 16384 || window.max < 16384 ||
			window.initial > maxWindow || window.max > maxWindow ||
			window.initial > window.max {
			return errors.New("legacy QUIC: invalid receive-window pair")
		}
	}
	return nil
}

// Only explicitly supplied safe fields override quicConfig's original
// defaults. The original TLS settings, packet masking and transport settings
// remain unchanged. The caller validates the values before dialing/listening.
func tunedLegacyQUICConfig(p *internet.QuicParams) *q.Config {
	config := quicConfig()
	if p == nil {
		return config
	}
	if p.MaxIdleTimeout != 0 {
		config.MaxIdleTimeout = time.Duration(p.MaxIdleTimeout) * time.Second
	}
	if p.KeepAlivePeriod != 0 {
		config.KeepAlivePeriod = time.Duration(p.KeepAlivePeriod) * time.Second
	}
	if p.MaxIncomingStreams != 0 {
		config.MaxIncomingStreams = p.MaxIncomingStreams
	}
	if p.InitStreamReceiveWindow != 0 {
		config.InitialStreamReceiveWindow = p.InitStreamReceiveWindow
		config.MaxStreamReceiveWindow = p.MaxStreamReceiveWindow
	}
	if p.InitConnReceiveWindow != 0 {
		config.InitialConnectionReceiveWindow = p.InitConnReceiveWindow
		config.MaxConnectionReceiveWindow = p.MaxConnReceiveWindow
	}
	return config
}
