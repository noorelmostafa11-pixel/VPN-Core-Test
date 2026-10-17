package conf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/quic"
)

// nodeLegacyQUICTuning accepts a connection-only subset of modern QUIC
// parameters for the independent legacy carrier. No arbitrary masks,
// certificates, socket options or browser fingerprint switches may be injected.
func nodeLegacyQUICTuning(fields *nodeFields) (*FinalMask, error) {
	present := false
	for _, key := range []string{"quicparams", "quic-params", "quic_params"} {
		if _, found := fields.values[key]; found {
			present = true
		}
	}
	raw := fields.take("quicparams", "quic-params", "quic_params")
	if !present {
		return nil, nil
	}
	if raw == "" || len(raw) > 4096 || raw[0] != '{' ||
		!nodeJSONObject(json.NewDecoder(bytes.NewReader([]byte(raw))), 0) {
		return nil, errors.New("node URI: invalid legacy QUIC tuning object")
	}
	var data struct {
		Congestion                   string `json:"congestion"`
		BbrProfile                   string `json:"bbrProfile"`
		BrutalUp                     Bandwidth `json:"brutalUp"`
		BrutalDown                   Bandwidth `json:"brutalDown"`
		BrutalDisableLossCompensation bool `json:"brutalDisableLossCompensation"`
		MaxIdleTimeout                int64  `json:"maxIdleTimeout"`
		KeepAlivePeriod               int64  `json:"keepAlivePeriod"`
		MaxIncomingStreams            int64  `json:"maxIncomingStreams"`
		InitStreamReceiveWindow       uint64 `json:"initStreamReceiveWindow"`
		MaxStreamReceiveWindow        uint64 `json:"maxStreamReceiveWindow"`
		InitConnectionReceiveWindow   uint64 `json:"initConnectionReceiveWindow"`
		MaxConnectionReceiveWindow    uint64 `json:"maxConnectionReceiveWindow"`
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&data) != nil {
		return nil, errors.New("node URI: unsupported legacy QUIC tuning field")
	}
	var rest any
	if decoder.Decode(&rest) != io.EOF {
		return nil, errors.New("node URI: invalid legacy QUIC tuning suffix")
	}
	up, err := data.BrutalUp.Bps()
	if err != nil {
		return nil, errors.New("node URI: invalid legacy QUIC upload rate")
	}
	down, err := data.BrutalDown.Bps()
	if err != nil {
		return nil, errors.New("node URI: invalid legacy QUIC download rate")
	}
	settings := &internet.QuicParams{
		Congestion: data.Congestion, BbrProfile: data.BbrProfile,
		BrutalUp: up, BrutalDown: down,
		BrutalDisableLossCompensation: data.BrutalDisableLossCompensation,
		MaxIdleTimeout:           data.MaxIdleTimeout,
		KeepAlivePeriod:          data.KeepAlivePeriod,
		MaxIncomingStreams:       data.MaxIncomingStreams,
		InitStreamReceiveWindow:  data.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:   data.MaxStreamReceiveWindow,
		InitConnReceiveWindow:    data.InitConnectionReceiveWindow,
		MaxConnReceiveWindow:     data.MaxConnectionReceiveWindow,
	}
	if err := quic.ValidateLegacyQUICParams(settings); err != nil {
		return nil, errors.New("node URI: unsupported legacy QUIC tuning values")
	}
	return &FinalMask{QuicParams: &QuicParamsConfig{
		Congestion: data.Congestion, BbrProfile: data.BbrProfile,
		BrutalUp: data.BrutalUp, BrutalDown: data.BrutalDown,
		BrutalDisableLossCompensation: data.BrutalDisableLossCompensation,
		MaxIdleTimeout:                data.MaxIdleTimeout,
		KeepAlivePeriod:               data.KeepAlivePeriod,
		MaxIncomingStreams:            data.MaxIncomingStreams,
		InitStreamReceiveWindow:       data.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:        data.MaxStreamReceiveWindow,
		InitConnectionReceiveWindow:   data.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:    data.MaxConnectionReceiveWindow,
	}}, nil
}
