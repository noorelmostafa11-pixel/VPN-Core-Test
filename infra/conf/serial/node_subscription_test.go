package serial_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

func subscriptionFixture() string {
	return "# synthetic fixtures only\n" +
		"vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443?type=ws\n" +
		"vmess://11111111-1111-4111-8111-111111111111@127.0.0.1:443?type=grpc&serviceName=test\n" +
		"trojan://synthetic@127.0.0.1:443?type=tcp\n" +
		"ss://aes-128-gcm:synthetic@127.0.0.1:443?type=tcp\n"
}

func TestAdditiveSubscriptionFourProtocolList(t *testing.T) {
	for label, payload := range map[string]string{
		"plain":subscriptionFixture(),
		"base64":base64.StdEncoding.EncodeToString([]byte(subscriptionFixture())),
		"url-base64":base64.RawURLEncoding.EncodeToString([]byte(subscriptionFixture())),
	} {
		t.Run(label,func(t *testing.T){
			c, err := serial.DecodeSubscriptionConfig(strings.NewReader(payload))
			if err != nil {t.Fatal(err)}
			if len(c.OutboundConfigs) != 4 {t.Fatal("subscription lost remote nodes")}
			for index, outbound := range c.OutboundConfigs {
				expected := []string{"vless","vmess","trojan","shadowsocks"}[index]
				if outbound.Protocol != expected && !(index==3 && outbound.Protocol=="shadowsocks") {
					t.Fatalf("node %d selected %s, expected %s",index,outbound.Protocol,expected)
				}
				if outbound.Tag=="" {t.Fatal("empty subscription tag")}
				if _,err:=outbound.Build();err!=nil{t.Fatal(err)}
			}
		})
	}
}

func TestAdditiveSubscriptionStrictRejection(t *testing.T) {
	for label,payload:=range map[string]string{
		"empty":"",
		"comments-only":"# no nodes\n\n",
		"fifth-protocol":"vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443\nwireguard://secret@127.0.0.1:1234\n",
		"unknown-scheme":"foo://private@127.0.0.1:443",
		"bad-encoded":"@not-base64!",
		"oversize":strings.Repeat("A",(1<<20)+1),
		"too-many-nodes":strings.Repeat("trojan://synthetic@127.0.0.1:443\n",129),
		"bad-uri-middle":"trojan://synthetic@127.0.0.1:443\nnot-a-node\nss://aes-128-gcm:synthetic@127.0.0.1:443",
	} {
		t.Run(label,func(t *testing.T) {
			if _,err:=serial.DecodeSubscriptionConfig(strings.NewReader(payload));err==nil{t.Fatal("invalid subscription was accepted")}
		})
	}
}

func TestAdditiveSubscriptionDoesNotReinterpretOriginalSingleURI(t *testing.T) {
	if _,err:=serial.DecodeURIConfig(strings.NewReader(subscriptionFixture()));err==nil{
		t.Fatal("existing URI reader was silently converted into a list reader")
	}
	for _, format:=range []string{"sub","subscription"}{
		if serial.ReaderDecoderByFormat[format]==nil {t.Fatal("subscription format not registered:",format)}
	}
}

func TestAdditiveSubscriptionErrorsDoNotLeakCredentials(t *testing.T) {
	secret := "synthetic-private-credential"
	_,err:=serial.DecodeSubscriptionConfig(strings.NewReader("trojan://"+secret+"@127.0.0.1:443?type=not-implemented"))
	if err==nil || strings.Contains(err.Error(),secret) {t.Fatal("subscription error exposed URI credentials")}
}
