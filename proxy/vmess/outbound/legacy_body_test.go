package outbound

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess"
)

func TestForkVMessBodySelection(t *testing.T) {
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_CFB, protocol.SecurityType_NONE, protocol.SecurityType_ZERO, protocol.SecurityType_AES128_GCM, protocol.SecurityType_CHACHA20_POLY1305} {
		request := &protocol.RequestHeader{Security: protocol.SecurityType_UNKNOWN, Command: protocol.RequestCommandTCP, Option: protocol.RequestOptionChunkStream}
		if err := configureRequestSecurity(request, &vmess.MemoryAccount{Security: security}); err != nil {
			t.Fatal(err)
		}
		if security == protocol.SecurityType_ZERO {
			if request.Security != protocol.SecurityType_NONE || request.Option != 0 {
				t.Fatal("zero was not raw NONE")
			}
			continue
		}
		if request.Security != security {
			t.Fatal("body mode substituted")
		}
		if security == protocol.SecurityType_NONE || security == protocol.SecurityType_AES128_CFB {
			if request.Option != protocol.RequestOptionChunkStream {
				t.Fatal("legacy default framing changed")
			}
		} else if !request.Option.Has(protocol.RequestOptionChunkMasking) || !request.Option.Has(protocol.RequestOptionGlobalPadding) {
			t.Fatal("modern AEAD defaults changed")
		}
	}
	for _, cmd := range []protocol.RequestCommand{protocol.RequestCommandUDP, protocol.RequestCommandMux} {
		if err := configureRequestSecurity(&protocol.RequestHeader{Command: cmd}, &vmess.MemoryAccount{Security: protocol.SecurityType_ZERO}); err == nil {
			t.Fatal("zero selected for non-TCP stream")
		}
	}
}
