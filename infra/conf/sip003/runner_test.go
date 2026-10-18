package sip003

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestSIP003HelperProcess(t *testing.T) {
	localPort:=os.Getenv("SS_LOCAL_PORT")
	if localPort==""{return}
	if os.Getenv("SS_LOCAL_HOST")!="127.0.0.1" ||
		os.Getenv("SS_REMOTE_HOST")!="127.0.0.1" ||
		os.Getenv("SS_REMOTE_PORT")!="443" ||
		os.Getenv("SS_PLUGIN_OPTIONS")!="obfs=http" {
		os.Exit(13)
	}
	ln,err:=net.Listen("tcp4","127.0.0.1:"+localPort)
	if err!=nil{os.Exit(14)}
	defer ln.Close()
	for {
		conn,err:=ln.Accept()
		if err!=nil{return}
		_ = conn.Close()
	}
}

func approvedHelper(t *testing.T) Approved {
	t.Helper()
	path,err:=os.Executable()
	if err!=nil{t.Fatal(err)}
	file,err:=os.Open(path)
	if err!=nil{t.Fatal(err)}
	defer file.Close()
	hash:=sha256.New()
	if _,err:=io.Copy(hash,file);err!=nil{t.Fatal(err)}
	return Approved{
		Name:"obfs-local",Executable:path,SHA256:hex.EncodeToString(hash.Sum(nil)),
		Args:[]string{"-test.run=^TestSIP003HelperProcess$"},
		StartupTimeout:3*time.Second,
	}
}

func TestApprovedSIP003ProcessLifecycleAndEnvironment(t *testing.T) {
	if testing.Short(){t.Skip("launches a pinned local test helper")}
	approved:=approvedHelper(t)
	ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second)
	defer cancel()
	process,err:=Start(ctx,approved,"127.0.0.1",443,"obfs=http")
	if err!=nil{t.Fatal(err)}
	t.Cleanup(func(){_ = process.Close()})
	address:="127.0.0.1:"+strconv.Itoa(int(process.LocalPort))
	conn,err:=net.DialTimeout("tcp4",address,300*time.Millisecond)
	if err!=nil{t.Fatal(err)}
	_ = conn.Close()
	if err:=process.Close();err!=nil{t.Fatal(err)}
	if err:=process.Close();err!=nil{t.Fatal("second close",err)}
}

func TestApprovedSIP003RejectsUnpinnedAndInvalidConfigurations(t *testing.T) {
	good:=approvedHelper(t)
	for label,bad:=range map[string]Approved{
		"unpinned":{Name:"obfs-local",Executable:good.Executable},
		"not-absolute":{Name:"obfs-local",Executable:"obfs-local",SHA256:good.SHA256},
		"wrong-sha":{Name:"obfs-local",Executable:good.Executable,SHA256:"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		"unsafe-name":{Name:"../shell",Executable:good.Executable,SHA256:good.SHA256},
		"unsafe-args":{Name:"obfs-local",Executable:good.Executable,SHA256:good.SHA256,Args:[]string{"-host\nInjected: value"}},
	}{
		t.Run(label,func(t *testing.T){
			if process,err:=Start(context.Background(),bad,"127.0.0.1",443,"obfs=http");err==nil{
				_ = process.Close()
				t.Fatal("unsafe executable configuration started")
			}
		})
	}
	if process,err:=Start(context.Background(),good,"127.0.0.1",0,"obfs=http");err==nil{
		_ = process.Close()
		t.Fatal("invalid target port accepted")
	}
	if process,err:=Start(context.Background(),good,"127.0.0.1",443,"obfs=http\nSS_REMOTE_HOST=evil");err==nil{
		_ = process.Close()
		t.Fatal("environment injection accepted")
	}
}
