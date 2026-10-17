package ssh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/net"
	sshlib "golang.org/x/crypto/ssh"
)

func TestSSHProtobufValidation(t *testing.T) {
	valid := func() *ClientConfig {
		return &ClientConfig{Address: net.NewIPOrDomain(net.LocalHostIP), Port: 22, Username: "user", Password: "synthetic", HostKey: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))}
	}
	if err := ValidateClient(valid()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ClientConfig){
		func(c *ClientConfig) { c.Address = nil },
		func(c *ClientConfig) { c.Address = &net.IPOrDomain{} },
		func(c *ClientConfig) { c.Address = &net.IPOrDomain{Address: &net.IPOrDomain_Ip{Ip: []byte{1}}} },
		func(c *ClientConfig) { c.Address = net.NewIPOrDomain(net.DomainAddress("bad:host")) },
		func(c *ClientConfig) { c.Address = net.NewIPOrDomain(net.DomainAddress("")) },
		func(c *ClientConfig) { c.Port = 65536 },
		func(c *ClientConfig) { c.Username = "u\nser" },
		func(c *ClientConfig) { c.Password = "" },
		func(c *ClientConfig) { c.Password = strings.Repeat("x", 4097) },
		func(c *ClientConfig) { c.HostKey = "" },
		func(c *ClientConfig) { c.PrivateKeyPassphrase = "unused" },
	} {
		c := valid()
		mutate(c)
		if err := ValidateClient(c); err == nil {
			t.Fatal("invalid direct protobuf accepted")
		}
	}
	if ValidateClient(nil) == nil || ValidateServer(nil) == nil || ValidateServer(&ServerConfig{}) == nil {
		t.Fatal("missing SSH authentication accepted")
	}
}

func TestSSHAuthorizedKeyFormatAndRestrictions(t *testing.T) {
	key, err := sshlib.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	line := sshlib.MarshalAuthorizedKey(key)
	data := append([]byte("# leading comment\n\r\n"), line...)
	data = append(data, line...)
	data = append(data, []byte("# trailing comment\r\n")...)
	if keys, err := authorizedKeys(data); err != nil || len(keys) != 1 {
		t.Fatal("valid comments/duplicates rejected", err)
	}
	for _, prefix := range []string{"from=\"127.0.0.1\" ", "command=\"forced\" ", "no-pty ", "restrict "} {
		if _, err := authorizedKeys(append([]byte(prefix), line...)); err == nil {
			t.Fatal("authorized-key restriction silently discarded", prefix)
		}
	}
	for _, data := range [][]byte{nil, []byte("# only comments\n"), []byte("malformed")} {
		if _, err := authorizedKeys(data); err == nil {
			t.Fatal("empty/malformed authorized keys accepted")
		}
	}
	var list bytes.Buffer
	for i := range 129 {
		public := make([]byte, ed25519.PublicKeySize)
		public[0] = byte(i)
		key, err := sshlib.NewPublicKey(ed25519.PublicKey(public))
		if err != nil {
			t.Fatal(err)
		}
		list.Write(sshlib.MarshalAuthorizedKey(key))
		_, err = authorizedKeys(list.Bytes())
		if (err == nil) != (i < 128) {
			t.Fatal("SSH authorized-key bound changed", i, err)
		}
	}
}

func TestSSHKeyFilesAreBoundedAndFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic.key")
	if _, err := boundedFile(dir, 65536); err == nil {
		t.Fatal("directory accepted as key file")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 65537)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fileSigner(path, ""); err == nil || strings.Contains(err.Error(), path) {
		t.Fatal("oversized private key accepted or file path exposed")
	}
	if err := os.WriteFile(path, []byte("not a private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fileSigner(path, ""); err == nil {
		t.Fatal("invalid SSH key accepted")
	}
}

func FuzzSSHProtobuf(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1}, "user", "synthetic", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", uint32(22))
	f.Fuzz(func(t *testing.T, ip []byte, user, password, pin string, port uint32) {
		c := &ClientConfig{Address: &net.IPOrDomain{Address: &net.IPOrDomain_Ip{Ip: ip}}, Username: user, Password: password, HostKey: pin, Port: port}
		ValidateClient(c)
	})
}
