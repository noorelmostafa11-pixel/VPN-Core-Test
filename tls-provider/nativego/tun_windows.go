//go:build windows

package nativego

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "syscall"
 "unsafe"
)

// WindowsWintun is a Go-only adapter for the verified, pinned Wintun DLL.
// The parent Windows host must own addresses, DNS, WFP and fail-closed routing.
type WindowsWintun struct {
 mu sync.Mutex
 dll *syscall.DLL
 closeAdapter *syscall.Proc
 endSession *syscall.Proc
 receive *syscall.Proc
 release *syscall.Proc
 sendAlloc *syscall.Proc
 send *syscall.Proc
 event *syscall.Proc
 adapter uintptr
 session uintptr
 closed bool
}

// OpenVerifiedWintun loads only the caller's absolute, content-pinned DLL.
// Trusting a DLL from PATH or disabling signature/integrity checks is forbidden.
// The official pinned Wintun 0.14.1 acquisition script publishes DLL SHA256.
func OpenVerifiedWintun(dllPath, expectedSHA256, adapterName string)(*WindowsWintun,error){
 if !filepath.IsAbs(dllPath)||!strings.EqualFold(filepath.Ext(dllPath),".dll")||adapterName==""||len(adapterName)>128 {
  return nil,errors.New("nativego: invalid Windows adapter or Wintun absolute path")
 }
 expected,err:=hex.DecodeString(expectedSHA256)
 if err!=nil||len(expected)!=sha256.Size {return nil,errors.New("nativego: Wintun DLL hash is mandatory")}
 f,err:=os.Open(dllPath);if err!=nil{return nil,err}
 sum:=sha256.New();_,err=io.Copy(sum,f);_=f.Close()
 if err!=nil{return nil,err}
 if string(sum.Sum(nil))!=string(expected){return nil,errors.New("nativego: Wintun DLL SHA256 mismatch")}
 name,err:=syscall.UTF16PtrFromString(adapterName);if err!=nil{return nil,err}
 typ,err:=syscall.UTF16PtrFromString("VpnCore-Go");if err!=nil{return nil,err}
 lib,err:=syscall.LoadDLL(dllPath);if err!=nil{return nil,err}
 d:=&WindowsWintun{dll:lib}
 cleanup:=func(e error)(*WindowsWintun,error){_=d.Close();return nil,e}
 find:=func(n string)(*syscall.Proc,error){return lib.FindProc(n)}
 create,err:=find("WintunCreateAdapter");if err!=nil{return cleanup(err)}
 d.closeAdapter,err=find("WintunCloseAdapter");if err!=nil{return cleanup(err)}
 start,err:=find("WintunStartSession");if err!=nil{return cleanup(err)}
 d.endSession,err=find("WintunEndSession");if err!=nil{return cleanup(err)}
 d.receive,err=find("WintunReceivePacket");if err!=nil{return cleanup(err)}
 d.release,err=find("WintunReleaseReceivePacket");if err!=nil{return cleanup(err)}
 d.sendAlloc,err=find("WintunAllocateSendPacket");if err!=nil{return cleanup(err)}
 d.send,err=find("WintunSendPacket");if err!=nil{return cleanup(err)}
 d.event,err=find("WintunGetReadWaitEvent");if err!=nil{return cleanup(err)}
 d.adapter,_,err=create.Call(uintptr(unsafe.Pointer(name)),uintptr(unsafe.Pointer(typ)),0)
 if d.adapter==0{return cleanup(fmt.Errorf("nativego: WintunCreateAdapter: %w",err))}
 d.session,_,err=start.Call(d.adapter,4*1024*1024)
 if d.session==0{return cleanup(fmt.Errorf("nativego: WintunStartSession: %w",err))}
 return d,nil
}

func(d *WindowsWintun)Read(b []byte)(int,error){
 d.mu.Lock();defer d.mu.Unlock()
 if d.closed||d.session==0{return 0,io.ErrClosedPipe}
 var size uint32
 p,_,callErr:=d.receive.Call(d.session,uintptr(unsafe.Pointer(&size)))
 if p==0 {
  if callErr!=syscall.Errno(259){return 0,fmt.Errorf("nativego: WintunReceivePacket: %w",callErr)}
  h,_,err:=d.event.Call(d.session)
  if h==0{return 0,fmt.Errorf("nativego: Wintun read event: %w",err)}
  _,err=syscall.WaitForSingleObject(syscall.Handle(h),50)
  if err!=nil{return 0,err}
  return 0,nil
 }
 defer d.release.Call(d.session,p)
 if size>uint32(len(b))||size>65535{return 0,io.ErrShortBuffer}
 n:=copy(b,unsafe.Slice((*byte)(unsafe.Pointer(p)),int(size)))
 return n,nil
}
func(d *WindowsWintun)Write(b []byte)(int,error){
 d.mu.Lock();defer d.mu.Unlock()
 if d.closed||d.session==0{return 0,io.ErrClosedPipe}
 if len(b)==0||len(b)>65535{return 0,errors.New("nativego: invalid Wintun packet size")}
 p,_,err:=d.sendAlloc.Call(d.session,uintptr(len(b)))
 if p==0{return 0,fmt.Errorf("nativego: WintunAllocateSendPacket: %w",err)}
 copy(unsafe.Slice((*byte)(unsafe.Pointer(p)),len(b)),b)
 d.send.Call(d.session,p)
 return len(b),nil
}
func(d *WindowsWintun)Close()error{
 d.mu.Lock();defer d.mu.Unlock()
 if d.closed{return nil}
 d.closed=true
 if d.session!=0&&d.endSession!=nil{d.endSession.Call(d.session);d.session=0}
 if d.adapter!=0&&d.closeAdapter!=nil{d.closeAdapter.Call(d.adapter);d.adapter=0}
 if d.dll!=nil{return d.dll.Release()}
 return nil
}
