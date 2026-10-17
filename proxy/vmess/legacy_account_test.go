package vmess_test

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess"
)

func TestForkVMessAccountPreservesBodyPolicy(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	for _, security := range []protocol.SecurityType{protocol.SecurityType_AES128_CFB, protocol.SecurityType_NONE, protocol.SecurityType_ZERO} {
		account, err := (&vmess.Account{Id: id, LegacyCompatibility: true, SecuritySettings: &protocol.SecurityConfig{Type: security}, AllowLegacyBody: true}).AsAccount()
		if err != nil {
			t.Fatal(err)
		}
		memory := account.(*vmess.MemoryAccount)
		if memory.Security != security || !memory.AllowLegacyBody || !memory.ToProto().(*vmess.Account).AllowLegacyBody {
			t.Fatal("body policy or explicit security lost")
		}
		if _, err := (&vmess.Account{Id: id, LegacyCompatibility: true, SecuritySettings: &protocol.SecurityConfig{Type: security}, TestsEnabled: "AuthenticatedLength"}).AsAccount(); err == nil {
			t.Fatal("protobuf bypassed experiment guard")
		}
	}
	if _, err := (&vmess.Account{Id: id, LegacyCompatibility: true, AlterId: 65}).AsAccount(); err == nil {
		t.Fatal("legacy alter ID limit bypassed")
	}
	if _, err := (&vmess.Account{Id: id, LegacyCompatibility: true, SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType(99)}}).AsAccount(); err == nil {
		t.Fatal("unknown protobuf security accepted")
	}
	account, err := (&vmess.Account{Id: id}).AsAccount()
	if err != nil || account.(*vmess.MemoryAccount).AllowLegacyBody {
		t.Fatal("default body policy weakened", err)
	}
}

func TestOriginalVMessProtobufAccount(t *testing.T) {
	for _, count := range []uint32{0, 16, 65, ^uint32(0)} {
		for _, security := range []protocol.SecurityType{protocol.SecurityType_AUTO, protocol.SecurityType_UNKNOWN, protocol.SecurityType(99)} {
			account, err := (&vmess.Account{Id: "00000000-0000-4000-8000-000000000001", AlterId: count, AllowLegacyBody: true, SecuritySettings: &protocol.SecurityConfig{Type: security}}).AsAccount()
			if err != nil {
				t.Fatal("original protobuf account newly rejected", err)
			}
			memory := account.(*vmess.MemoryAccount)
			if len(memory.AlterIDs) != 0 || memory.AllowLegacyBody || memory.LegacyCompatibility || memory.Security != (&protocol.SecurityConfig{Type: security}).GetSecurityType() {
				t.Fatal("original protobuf account opted into legacy behavior")
			}
		}
	}
}
