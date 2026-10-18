package conf

import "errors"

// Opt-in HTTP2 connection metadata; original native HTTP2 builder keeps
// responsibility for method, timeouts and reserved-header validation.
func nodeHTTP2Extensions(fields *nodeFields, cfg *HTTPConfig) error {
	cfg.Method = fields.take("httpmethod", "http-method")
	if cfg.Method != "" && (len(cfg.Method) > 32 || !nodeHTTPHeaderToken(cfg.Method)) {
		return errors.New("node URI: invalid HTTP2 method")
	}
	idle, err := nodeTransportUint32(fields, 0, 600, "httpreadidletimeout", "http-read-idle-timeout")
	if err != nil {
		return err
	}
	health, err := nodeTransportUint32(fields, 0, 60, "httphealthchecktimeout", "http-health-check-timeout")
	if err != nil {
		return err
	}
	if health > 0 && idle == 0 {
		return errors.New("node URI: HTTP2 health check without idle timeout")
	}
	cfg.ReadIdleTimeout, cfg.HealthCheckTimeout = int32(idle), int32(health)
	headers, err := nodeHTTPTransportHeaders(fields, "httpheaders", "http-headers")
	if err != nil {
		return err
	}
	if len(headers) > 0 {
		cfg.Headers = make(map[string]*StringList, len(headers))
		for key, value := range headers {
			list := StringList{value}
			cfg.Headers[key] = &list
		}
	}
	return nil
}
