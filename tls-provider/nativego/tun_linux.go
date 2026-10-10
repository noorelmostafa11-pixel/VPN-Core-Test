//go:build linux

package nativego

import (
 "errors"
 "io"
 "strings"
 "sync/atomic"

 "golang.org/x/sys/unix"
)

// LinuxTUN is a pure-Go, bounded, nonblocking /dev/net/tun packet device.
// Interface addresses, routes, DNS and nftables belong to the privileged host.
type LinuxTUN struct {
 fd int
 closed atomic.Bool
}

// OpenNamedLinuxTUN creates an IFF_TUN|IFF_NO_PI device. It neither enables
// routes nor weakens an existing firewall and requires CAP_NET_ADMIN.
func OpenNamedLinuxTUN(name string)(*LinuxTUN,error){
 if name==""||len(name)>=unix.IFNAMSIZ||strings.IndexByte(name,0)>=0{
  return nil,errors.New("nativego: invalid TUN interface name")
 }
 request,err:=unix.NewIfreq(name)
 if err!=nil{return nil,err}
 request.SetUint16(unix.IFF_TUN|unix.IFF_NO_PI)
 fd,err:=unix.Open("/dev/net/tun",unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK,0)
 if err!=nil{return nil,err}
 if err=unix.IoctlIfreq(fd,unix.TUNSETIFF,request);err!=nil{
  _=unix.Close(fd);return nil,err
 }
 return &LinuxTUN{fd:fd},nil
}
func(d *LinuxTUN)Read(b []byte)(int,error){
 if len(b)==0{return 0,io.ErrShortBuffer}
 for{
  if d.closed.Load(){return 0,io.ErrClosedPipe}
  n,err:=unix.Read(d.fd,b)
  if err==unix.EINTR{continue}
  if err==unix.EAGAIN||err==unix.EWOULDBLOCK{
   _,_ = unix.Poll([]unix.PollFd{{Fd:int32(d.fd),Events:unix.POLLIN}},50)
   continue
  }
  return n,err
 }
}
func(d *LinuxTUN)Write(b []byte)(int,error){
 if len(b)==0||len(b)>65535{return 0,errors.New("nativego: invalid outgoing IP packet")}
 for{
  if d.closed.Load(){return 0,io.ErrClosedPipe}
  n,err:=unix.Write(d.fd,b)
  if err==unix.EINTR{continue}
  if err==unix.EAGAIN||err==unix.EWOULDBLOCK{
   _,_ = unix.Poll([]unix.PollFd{{Fd:int32(d.fd),Events:unix.POLLOUT}},50)
   continue
  }
  return n,err
 }
}
func(d *LinuxTUN)Close()error{
 if d.closed.Swap(true){return nil}
 return unix.Close(d.fd)
}
