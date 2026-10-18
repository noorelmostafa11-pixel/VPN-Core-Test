package conf_test

import (
	"encoding/base64"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

// VMess JSON share envelopes accept object-form headers only through the same
// WS/HTTPUpgrade validation and transport builders used by string/URI inputs.
func vmessJSONHeadersObjectLink(network, headersJSON string) string {
	body := `{"v":"2","add":"127.0.0.1","port":"443","id":"11111111-1111-4111-8111-111111111111","aid":0,"scy":"auto","net":` +
		strconv.Quote(network) + `,"type":"none","headers":` + headersJSON + `}`
	return "vmess://" + base64.RawStdEncoding.EncodeToString([]byte(body))
}

func TestAddedVMessJSONHeadersObjectMatchesStringWireConfig(t *testing.T) {
	const object = `{"X-Route":"synthetic","X-Client":"test"}`
	for _, network := range []string{"ws", "httpupgrade"} {
		t.Run(network, func(t *testing.T) {
			fromObject, err := conf.ParseNodeURI(vmessJSONHeadersObjectLink(network, object))
			if err != nil {
				t.Fatal("object-form headers rejected:", err)
			}
			fromString, err := conf.ParseNodeURI(vmessJSONHeadersObjectLink(network, strconv.Quote(object)))
			if err != nil {
				t.Fatal("previously supported string-form headers rejected:", err)
			}
			objectStream, err := fromObject.StreamSetting.Build()
			if err != nil {
				t.Fatal(err)
			}
			stringStream, err := fromString.StreamSetting.Build()
			if err != nil {
				t.Fatal(err)
			}
			if !addedConfigEqual(objectStream, stringStream) {
				t.Fatal("object and string headers changed transport wire settings")
			}
			if _, err := fromObject.Build(); err != nil {
				t.Fatal("object-form outbound did not build:", err)
			}
		})
	}
}

func TestAddedVMessJSONHeadersObjectRejectsUnsafe(t *testing.T) {
	for _, item := range []struct {
		name, network, raw string
	}{
		{"host", "ws", `{"Host":"override.invalid"}`},
		{"upgrade", "httpupgrade", `{"Connection":"close"}`},
		{"duplicate", "ws", `{"X-Route":"one","X-Route":"two"}`},
		{"case-duplicate", "ws", `{"X-Route":"one","x-route":"two"}`},
		{"non-string-value", "ws", `{"X-Route":123}`},
		{"injected-newline", "httpupgrade", `{"X-Route":"line\r\nX-Evil: yes"}`},
		{"empty-object", "ws", `{}`},
		{"array", "ws", `["x"]`},
		{"wrong-transport", "tcp", `{"X-Route":"synthetic"}`},
		{"grpc", "grpc", `{"X-Route":"synthetic"}`},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := conf.ParseNodeURI(vmessJSONHeadersObjectLink(item.network, item.raw)); err == nil {
				t.Fatal("unsafe VMess JSON object headers accepted")
			}
		})
	}
}

// Null is an ignored VMess share-envelope field today; do not reinterpret it
// as a request to add an empty header map or reject previously valid links.
func TestAddedVMessJSONHeadersNullPreservesIgnoredEnvelope(t *testing.T) {
	out, err := conf.ParseNodeURI(vmessJSONHeadersObjectLink("ws", `null`))
	if err != nil {
		t.Fatal("previously ignored null changed behavior:", err)
	}
	if len(out.StreamSetting.WSSettings.Headers) != 0 {
		t.Fatal("null injected transport headers")
	}
	if _, err := out.Build(); err != nil {
		t.Fatal(err)
	}
}
