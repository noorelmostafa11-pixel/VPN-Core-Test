package core

import (
	"errors"
	"net/url"
	"strings"
)

// Hysteria 1 uses the v3 binary protocol, not Hysteria 2's HTTP/3 auth.
func parseHysteria1URI(uri string) (Config, error) {
	c := defaults()
	c.OriginalURI = uri
	c.Protocol, c.Transport, c.Security = "hysteria", "quic", "tls"
	u, err := url.Parse(uri)
	if err != nil || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery == "" {
		return c, errors.New("HYSTERIA1_URI_INVALID")
	}
	c.Server, c.ServerName = u.Hostname(), u.Hostname()
	c.Port, err = number(u.Port(), 1, 65535)
	if err != nil {
		return c, err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return c, errors.New("HYSTERIA1_URI_INVALID")
	}
	c.Options = map[string]string{}
	for k, v := range q {
		key := strings.ToLower(k)
		if len(v) != 1 {
			return c, errors.New("HYSTERIA1_DUPLICATE_OPTION")
		}
		if _, ok := c.Options[key]; ok {
			return c, errors.New("HYSTERIA1_DUPLICATE_OPTION")
		}
		c.Options[key] = v[0]
	}
	c.Password = c.Options["auth"]
	c.ServerName = option(c.Options, c.Server, "peer", "sni")
	c.Fingerprint = option(c.Options, "native", "fp", "fingerprint")
	c.InsecureRequested = truth(option(c.Options, "", "insecure", "allowinsecure"))
	c.ECH = c.Options["ech"]
	c.ALPN = strings.Split(option(c.Options, "hysteria", "alpn"), ",")
	return c, c.Validate()
}
func validateHysteria1Common(options map[string]string) error {
	for _, k := range []string{"upmbps", "downmbps"} {
		if _, err := number(options[k], 1, 100000); err != nil {
			return errors.New("HYSTERIA1_BANDWIDTH_INVALID")
		}
	}
	if option(options, "udp", "protocol") != "udp" {
		return errors.New("HYSTERIA1_CARRIER_UNSUPPORTED")
	}
	if mode := option(options, "", "obfs"); mode != "" && mode != "xplus" {
		return errors.New("HYSTERIA1_OBFS_UNSUPPORTED")
	}
	key := option(options, "", "obfsparam", "obfs-password")
	if (options["obfs"] == "xplus") != (key != "") || len(key) > 4096 {
		return errors.New("HYSTERIA1_OBFS_INVALID")
	}
	alpn := strings.Split(option(options, "hysteria", "alpn"), ",")
	if len(alpn) > 8 {
		return errors.New("HYSTERIA1_ALPN_INVALID")
	}
	for _, v := range alpn {
		if len(v) == 0 || len(v) > 255 {
			return errors.New("HYSTERIA1_ALPN_INVALID")
		}
	}
	return nil
}
func validateHysteria1(c Config) error {
	if !hostValid(c.Server) || c.Port < 1 || c.Port > 65535 || len(c.Password) > 4096 || c.Transport != "quic" || c.Security != "tls" {
		return errors.New("HYSTERIA1_CONFIGURATION")
	}
	for k := range c.Options {
		if !contains([]string{"auth", "peer", "sni", "insecure", "allowinsecure", "fp", "fingerprint", "ech", "protocol", "upmbps", "downmbps", "alpn", "obfs", "obfsparam", "obfs-password", "pinsha256", "pcs", "vcn"}, k) {
			return errors.New("HYSTERIA1_OPTION_UNSUPPORTED")
		}
	}
	if c.Fingerprint != "native" && c.Fingerprint != "" {
		return errors.New("HYSTERIA1_FINGERPRINT_UNSUPPORTED")
	}
	if err := validateHysteria1Common(c.Options); err != nil {
		return err
	}
	_, err := c.tlsSettings()
	return err
}
func validateHysteria1Server(c ServerConfig) error {
	if len(c.UUIDs) != 0 || c.Cipher != "" {
		return errors.New("HYSTERIA1_SERVER_CONFIGURATION")
	}
	for k, v := range c.Options {
		if !contains([]string{"protocol", "upmbps", "downmbps", "alpn", "obfs", "obfsparam", "obfs-password", "disable-udp"}, k) {
			return errors.New("HYSTERIA1_SERVER_OPTION_UNSUPPORTED")
		}
		if k == "disable-udp" && v != "true" && v != "false" {
			return errors.New("HYSTERIA1_SERVER_CONFIGURATION")
		}
	}
	return validateHysteria1Common(c.Options)
}
