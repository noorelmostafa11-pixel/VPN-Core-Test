package vmess_test

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess"
)

func TestForkVMessAccountPreservesBodyPolicy(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_CFB, protocol.SecurityType_NONE, protocol.SecurityType_ZERO} {
		account, err := (&vmess.Account{Id: id, SecuritySettings: &protocol.SecurityConfig{Type: security}, AllowLegacyBody: true}).AsAccount()
		if err != nil {
			t.Fatal(err)
		}
		memory := account.(*vmess.MemoryAccount)
		if memory.Security != security || !memory.AllowLegacyBody || !memory.ToProto().(*vmess.Account).AllowLegacyBody {
			t.Fatal("body policy or explicit security lost")
		}
		if _, err := (&vmess.Account{Id: id, SecuritySettings: &protocol.SecurityConfig{Type: security}, TestsEnabled: "AuthenticatedLength"}).AsAccount(); err == nil {
			t.Fatal("protobuf bypassed experiment guard")
		}
	}
	if _, err := (&vmess.Account{Id: id, AlterId: 65}).AsAccount(); err == nil {
		t.Fatal("legacy alter ID limit bypassed")
	}
	if _, err := (&vmess.Account{Id: id, SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType(99)}}).AsAccount(); err == nil {
		t.Fatal("unknown protobuf security accepted")
	}
	account, err := (&vmess.Account{Id: id}).AsAccount()
	if err != nil || account.(*vmess.MemoryAccount).AllowLegacyBody {
		t.Fatal("default body policy weakened", err)
	}
}
