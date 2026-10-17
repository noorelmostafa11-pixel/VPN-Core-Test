# Same-batch additional XHTTP capability: bounded download-only request headers

Parent 7ea800845a1e176faca605ebbebbc82b1c5b2183. Use `extra.downloadSettings.xhttpSettings.headers` with a JSON map (ordinary HTTP token keys and UTF-8 values only). Maximum 32 headers, 128-byte key, 2048-byte values; no Host, Connection, Upgrade, Content-Length, Sec-WebSocket handshake, Transfer-Encoding or other reserved headers. Host is controlled solely by XHTTP's dedicated connection setting; all other validation and pre-existing URI behavior stays unchanged.

The optional feature is handled by the existing SplitHTTPConfig.Headers and Build implementation. The nested validator rejects control bytes, case-ambiguous duplicate keys, unknown download fields and file-based directives. Config parity and rejection fixtures added for VLESS/VMess/Trojan/Shadowsocks. Full Go1.27.1 module tests, third-party XHTTP interoperability and Windows/macOS runs are NOT_VERIFIED, as requested for the final gate.

This is not a generic arbitrary nested-config importer, and not a new VPN protocol.
