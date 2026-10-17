package ssh

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	sshlib "golang.org/x/crypto/ssh"
)

type Client struct {
	server net.Destination
	config *sshlib.ClientConfig
	policy policy.Session
}

func NewClient(ctx context.Context, c *ClientConfig) (*Client, error) {
	config, err := clientConfig(c)
	if err != nil {
		return nil, err
	}
	manager := core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager)
	return &Client{server: net.TCPDestination(c.Address.AsAddress(), net.Port(c.Port)), config: config, policy: manager.ForLevel(c.UserLevel)}, nil
}

type directTCPIP struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 || !outbounds[len(outbounds)-1].Target.IsValid() {
		return errors.New("SSH target is missing")
	}
	ob := outbounds[len(outbounds)-1]
	target := ob.Target
	if target.Network != net.Network_TCP {
		return errors.New("SSH supports TCP forwarding only")
	}
	if target.Address == nil || target.Port == 0 {
		return errors.New("invalid SSH TCP target")
	}
	host := target.Address.String()
	if target.Address.Family().IsIP() {
		host = target.Address.IP().String()
	}
	if !validHost(host) {
		return errors.New("invalid SSH TCP target")
	}
	ob.Name, ob.CanSpliceCopy = "ssh", 3
	// One transport belongs to one flow. There is no reconnect, alternative
	// protocol or replay of application bytes after authentication failure.
	raw, err := dialer.Dial(ctx, c.server)
	if err != nil {
		return errors.New("SSH server connection failed")
	}
	defer raw.Close()
	stop := closeOnCancel(ctx, func() { raw.Close() })
	defer stop()
	if err := raw.SetDeadline(time.Now().Add(c.policy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to bound SSH handshake")
	}
	conn, channels, requests, err := sshlib.NewClientConn(raw, c.server.NetAddr(), c.config)
	if err != nil {
		return errors.New("SSH host verification or authentication failed")
	}
	var workers sync.WaitGroup
	defer func() {
		raw.Close()
		conn.Close()
		conn.Wait()
		workers.Wait()
	}()
	workers.Add(2)
	go func() {
		defer workers.Done()
		sshlib.DiscardRequests(requests)
	}()
	go func() {
		defer workers.Done()
		for channel := range channels {
			channel.Reject(sshlib.UnknownChannelType, "unsupported channel")
		}
	}()
	payload := directTCPIP{Host: host, Port: uint32(target.Port), OriginHost: "127.0.0.1"}
	channel, replies, err := conn.OpenChannel("direct-tcpip", sshlib.Marshal(payload))
	if err != nil {
		return errors.New("SSH TCP forwarding request failed")
	}
	defer channel.Close()
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return errors.New("unable to clear SSH handshake deadline")
	}
	return relay(ctx, channel, replies, link, c.policy.Timeouts, false, func() { raw.Close() })
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
