//go:build linux || android

package nativego

import (
 "errors"
 "os"
 "syscall"
)

// OpenBorrowedTunFD duplicates the caller's established Linux/Android TUN FD.
// Android VpnService keeps its original FD and must protect node sockets first.
// Neither this function nor the engine modifies routes or firewall rules.
func OpenBorrowedTunFD(fd int)(*os.File,error){
 if fd<0{return nil,errors.New("nativego: TUN FD is invalid")}
 duplicate,err:=syscall.Dup(fd)
 if err!=nil{return nil,err}
 syscall.CloseOnExec(duplicate)
 return os.NewFile(uintptr(duplicate),"vpn-native-go-tun"),nil
}
