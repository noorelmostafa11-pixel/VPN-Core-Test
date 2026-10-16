package udp

import (
	"fmt"

	"github.com/xtls/xray-core/common/net"
)

type Server struct {
	Port         net.Port
	MsgProcessor func(msg []byte) []byte
	conn         *net.UDPConn
	done         chan struct{}
}

func (server *Server) Start() (net.Destination, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   []byte{127, 0, 0, 1},
		Port: int(server.Port),
		Zone: "",
	})
	if err != nil {
		return net.Destination{}, err
	}
	server.Port = net.Port(conn.LocalAddr().(*net.UDPAddr).Port)
	fmt.Println("UDP server started on port ", server.Port)

	server.conn = conn
	server.done = make(chan struct{})
	go server.handleConnection(conn, server.done)
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return net.UDPDestination(net.IPAddress(localAddr.IP), net.Port(localAddr.Port)), nil
}

func (server *Server) handleConnection(conn *net.UDPConn, done chan struct{}) {
	defer close(done)
	for {
		buffer := make([]byte, 2*1024)
		nBytes, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("Failed to read from UDP: %v\n", err)
			return
		}

		response := server.MsgProcessor(buffer[:nBytes])
		if _, err := conn.WriteToUDP(response, addr); err != nil {
			fmt.Println("Failed to write to UDP: ", err.Error())
		}
	}
}

func (server *Server) Close() error {
	if server.conn == nil {
		return nil
	}
	err := server.conn.Close()
	<-server.done
	return err
}
