package hysteria1

import (
    "bytes"
    "errors"
    "net"
    "sync"
    "testing"
    "time"
)
func TestAuthenticatedV3Control(t *testing.T){
    for _,good:=range []bool{true,false}{
        a,b:=net.Pipe()
        _=a.SetDeadline(time.Now().Add(time.Second*2))
        _=b.SetDeadline(time.Now().Add(time.Second*2))
        var wg sync.WaitGroup
        wg.Add(1)
        go func(){
            defer wg.Done()
            _,err:=ServerHandshake(b,"synthetic-secret",Rates{Upload:20_000_000,Download:10_000_000})
            if good && err!=nil{t.Error(err)}
            if !good && !errors.Is(err,ErrAuthentication){t.Error(err)}
        }()
        password:="wrong"
        if good{password="synthetic-secret"}
        rate,err:=ClientHandshake(a,password,Rates{Upload:15_000_000,Download:30_000_000})
        if good&&(err!=nil||rate.Upload!=10_000_000||rate.Download!=20_000_000){t.Error(rate,err)}
        if !good&&!errors.Is(err,ErrAuthentication){t.Error(err)}
        wg.Wait()
        a.Close()
        b.Close()
    }
}
func TestRequestAck(t *testing.T){
    a,b:=net.Pipe()
    defer a.Close()
    defer b.Close()
    _=a.SetDeadline(time.Now().Add(time.Second))
    _=b.SetDeadline(time.Now().Add(time.Second))
    done:=make(chan error,1)
    go func(){
        req,err:=ReadRequest(b)
        if err!=nil{done<-err;return}
        if !req.UDP||req.Host!=""||req.Port!=0{done<-ErrWire;return}
        done<-SendResponse(b,true,7)
    }()
    id,err:=RequestUDP(a)
    if err!=nil||id!=7{t.Fatal(id,err)}
    if err:=<-done;err!=nil{t.Fatal(err)}
    _,err=ClientHandshake(&bytes.Buffer{},"secret",Rates{Upload:0,Download:1})
    if !errors.Is(err,ErrWire){t.Fatal(err)}
}
