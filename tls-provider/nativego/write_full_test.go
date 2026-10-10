package nativego

import (
 "bytes"
 "errors"
 "io"
 "testing"
)

type partialWriter struct{out bytes.Buffer;zero bool}
func(w *partialWriter)Write(p []byte)(int,error){
 if w.zero{return 0,nil}
 n:=len(p);if n>2{n=2}
 return w.out.Write(p[:n])
}
func TestWriteFullHandlesShortWrites(t *testing.T){
 w:=&partialWriter{}
 b:=[]byte("authenticated-frame-not-truncated")
 if err:=writeFull(w,b);err!=nil{t.Fatal(err)}
 if !bytes.Equal(w.out.Bytes(),b){t.Fatalf("incomplete frame: %q",w.out.String())}
}
func TestWriteFullRejectsZeroProgress(t *testing.T){
 if err:=writeFull(&partialWriter{zero:true},[]byte("data"));!errors.Is(err,io.ErrShortWrite){t.Fatalf("got %v",err)}
}
