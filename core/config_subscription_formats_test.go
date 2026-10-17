package core_test

import (
 "testing"
 "github.com/xtls/xray-core/core"
)

func TestFourProtocolSubscriptionFormatExtensions(t *testing.T) {
 for ext,want:=range map[string]string{
  "sub":"subscription","subscription":"subscription",
  "subjson":"subjson","node-list":"subjson",
  "uri":"uri","node":"node","json":"json","yaml":"yaml",
 } {
  t.Run(ext,func(t *testing.T){if got:=core.GetFormatByExtension(ext);got!=want{t.Fatalf("got %q, expected %q",got,want)}})
 }
 for name,want:=range map[string]string{
  "nodes.sub":"subscription","nodes.subscription":"subscription",
  "nodes.subjson":"subjson","nodes.node-list":"subjson",
  "single.uri":"uri","single.node":"node",
 } {
  if got:=core.GetFormat(name);got!=want{t.Fatalf("file %q detected as %q; expected %q",name,got,want)}
 }
}
