package ssh

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
	sshlib "golang.org/x/crypto/ssh"
)

type Server struct {
	config *sshlib.ServerConfig
	policy policy.Session
	level  uint32
	slots  chan struct{}
}

func NewServer(ctx context.Context, c *ServerConfig) (*Server, error) {
	config, err := serverConfig(c)
	if err != nil {
		return nil, err
	}
	manager := core.MustFromContext(ctx).GetFeature(policy.ManagerType()).(policy.Manager)
	return &Server{config: config, policy: manager.ForLevel(c.UserLevel), level: c.UserLevel, slots: make(chan struct{}, 64)}, nil
}

func (*Server) Network() []net.Network { return []net.Network{net.Network_TCP} }

type activeConnection struct {
	net.Conn
	activity
}

func (c *activeConnection) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.Update()
	}
	return n, err
}

func (c *activeConnection) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.Update()
	}
	return n, err
}

func (s *Server) Process(ctx context.Context, network net.Network, raw stat.Connection, dispatcher routing.Dispatcher) error {
	if network != net.Network_TCP {
		return errors.New("SSH accepts TCP only")
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return errors.New("SSH connection limit reached")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := closeOnCancel(ctx, func() { raw.Close() })
	defer stop()
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(s.policy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to bound SSH handshake")
	}
	active := &activeConnection{Conn: raw, activity: activity{start: time.Now()}}
	active.Update()
	conn, channels, requests, err := sshlib.NewServerConn(active, s.config)
	if err != nil {
		return errors.New("SSH handshake or authentication failed")
	}
	var workers sync.WaitGroup
	defer func() {
		cancel()
		raw.Close()
		conn.Close()
		conn.Wait()
		workers.Wait()
	}()
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return errors.New("unable to clear SSH handshake deadline")
	}
	workers.Add(2)
	go func() {
		defer workers.Done()
		for request := range requests {
			// Keepalive is harmless; remote forwarding and all other global
			// operations are refused. No shell/session handler is installed.
			request.Reply(request.Type == "keepalive@openssh.com" && len(request.Payload) == 0, nil)
		}
	}()
	go func() {
		defer workers.Done()
		timeout := s.policy.Timeouts.ConnectionIdle
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				left := timeout - active.idle()
				if left <= 0 || timeout <= 0 {
					cancel()
					return
				}
				timer.Reset(left)
			}
		}
	}()
	slots := make(chan struct{}, 64)
	for next := range channels {
		target, err := channelDestination(next)
		if err != nil {
			next.Reject(sshlib.Prohibited, "unsupported TCP forwarding request")
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			next.Reject(sshlib.ResourceShortage, "channel limit reached")
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			s.processChannel(ctx, next, target, dispatcher, func() { raw.Close() })
		}()
	}
	return nil
}

func channelDestination(channel sshlib.NewChannel) (net.Destination, error) {
	var request directTCPIP
	if channel.ChannelType() != "direct-tcpip" || len(channel.ExtraData()) > 1024 || sshlib.Unmarshal(channel.ExtraData(), &request) != nil || request.Port == 0 || request.Port > 65535 || request.OriginPort > 65535 || !validHost(request.Host) || !validHost(request.OriginHost) {
		return net.Destination{}, errors.New("invalid SSH forwarding request")
	}
	return net.TCPDestination(net.ParseAddress(request.Host), net.Port(request.Port)), nil
}

func (s *Server) processChannel(ctx context.Context, next sshlib.NewChannel, target net.Destination, dispatcher routing.Dispatcher, abortTransport func()) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Dispatcher mutates session metadata. Each multiplexed channel owns its
	// own inbound/content/outbound values rather than racing its siblings.
	inbound := session.Inbound{Name: "ssh", CanSpliceCopy: 3, User: &protocol.MemoryUser{Level: s.level}}
	if parent := session.InboundFromContext(ctx); parent != nil {
		inbound.Source, inbound.Local, inbound.Gateway, inbound.Tag = parent.Source, parent.Local, parent.Gateway, parent.Tag
	}
	content := session.Content{}
	if parent := session.ContentFromContext(ctx); parent != nil {
		content = *parent
		if parent.Attributes != nil {
			content.Attributes = make(map[string]string, len(parent.Attributes))
			for key, value := range parent.Attributes {
				content.Attributes[key] = value
			}
		}
	}
	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithContent(ctx, &content)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	link, err := dispatcher.Dispatch(ctx, target)
	if err != nil {
		next.Reject(sshlib.ConnectionFailed, "routing failed")
		return
	}
	defer common.Interrupt(link.Reader)
	defer common.Interrupt(link.Writer)
	channel, requests, err := next.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	relay(ctx, channel, requests, link, s.policy.Timeouts, true, abortTransport)
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
