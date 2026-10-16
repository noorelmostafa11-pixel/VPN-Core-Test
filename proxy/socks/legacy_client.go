package socks

import (
	"context"
	"encoding/binary"
	"io"
	"strings"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func validateLegacyUser(user *protocol.MemoryUser) error {
	if user == nil {
		return nil
	}
	account, ok := user.Account.(*Account)
	if !ok || account == nil {
		return errors.New("invalid SOCKS4/4a account type")
	}
	if account.Password != "" || len(account.Username) > 255 || strings.ContainsAny(account.Username, "\x00\r\n") {
		return errors.New("SOCKS4/4a requires a bounded user ID without a password")
	}
	return nil
}

func resolveLegacyIPv4(ctx context.Context, domain string, lookup func(context.Context, string) ([]net.IPAddr, error)) (net.Address, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ips, err := lookup(ctx, domain)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, candidate := range ips {
		if ip := candidate.IP.To4(); ip != nil {
			return net.IPAddress(ip), nil
		}
	}
	return nil, errors.New("SOCKS4 requires an IPv4 destination")
}

func clientHandshake4(request *protocol.RequestHeader, reader io.Reader, writer io.Writer) (*protocol.RequestHeader, error) {
	if request.Command != protocol.RequestCommandTCP {
		return nil, errors.New("SOCKS4/4a supports TCP CONNECT only")
	}
	if request.Address == nil || request.Port == 0 {
		return nil, errors.New("SOCKS4/4a requires a destination and nonzero port")
	}
	if err := validateLegacyUser(request.User); err != nil {
		return nil, err
	}
	var ip []byte
	var domain string
	if request.Address.Family().IsDomain() {
		domain = request.Address.Domain()
		if domain == "" || len(domain) > 255 || strings.ContainsAny(domain, "\x00\r\n") {
			return nil, errors.New("invalid SOCKS4a destination domain")
		}
		ip = []byte{0, 0, 0, 1}
	} else {
		ip = request.Address.IP().To4()
		if ip == nil || (ip[0] == 0 && ip[1] == 0 && ip[2] == 0) {
			return nil, errors.New("SOCKS4/4a destination is not a usable IPv4 address")
		}
	}
	userID := ""
	if request.User != nil {
		userID = request.User.Account.(*Account).Username
	}
	packet := make([]byte, 8, 10+len(userID)+len(domain))
	packet[0], packet[1] = socks4Version, cmdTCPConnect
	binary.BigEndian.PutUint16(packet[2:4], uint16(request.Port))
	copy(packet[4:8], ip)
	packet = append(packet, userID...)
	packet = append(packet, 0)
	if domain != "" {
		packet = append(packet, domain...)
		packet = append(packet, 0)
	}
	if err := buf.WriteAllBytes(writer, packet, nil); err != nil {
		return nil, err
	}
	var reply [8]byte
	if _, err := io.ReadFull(reader, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 0 || reply[1] != socks4RequestGranted {
		return nil, errors.New("SOCKS4/4a request rejected: ", reply[1])
	}
	return nil, nil
}
