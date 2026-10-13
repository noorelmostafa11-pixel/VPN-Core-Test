// Project-owned adapter hook. The QUIC library retains packet protection,
// congestion control and stream framing; this hook only selects its TLS client.
package quicbridge

import (
	"context"
	"crypto/tls"
)

type Conn interface {
	Start(context.Context) error
	NextEvent() tls.QUICEvent
	Close() error
	HandleData(tls.QUICEncryptionLevel, []byte) error
	SendSessionTicket(tls.QUICSessionTicketOptions) error
	StoreSession(*tls.SessionState) error
	ConnectionState() tls.ConnectionState
	SetTransportParameters([]byte)
}
type Factory func(context.Context, *tls.Config) (Conn, error)
type factoryKey struct{}

func WithFactory(ctx context.Context, factory Factory) context.Context {
	return context.WithValue(ctx, factoryKey{}, factory)
}

type lazyClient struct {
	config *tls.Config
	conn   Conn
	params []byte
}

func NewClient(config *tls.Config) Conn { return &lazyClient{config: config} }
func (c *lazyClient) Start(ctx context.Context) error {
	if f, ok := ctx.Value(factoryKey{}).(Factory); ok {
		var err error
		c.conn, err = f(ctx, c.config)
		if err != nil {
			return err
		}
	} else {
		c.conn = tls.QUICClient(&tls.QUICConfig{TLSConfig: c.config, EnableSessionEvents: true})
	}
	c.conn.SetTransportParameters(c.params)
	return c.conn.Start(ctx)
}
func (c *lazyClient) NextEvent() tls.QUICEvent { return c.conn.NextEvent() }
func (c *lazyClient) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
func (c *lazyClient) HandleData(l tls.QUICEncryptionLevel, b []byte) error {
	return c.conn.HandleData(l, b)
}
func (c *lazyClient) SendSessionTicket(o tls.QUICSessionTicketOptions) error {
	return c.conn.SendSessionTicket(o)
}
func (c *lazyClient) StoreSession(s *tls.SessionState) error { return c.conn.StoreSession(s) }
func (c *lazyClient) ConnectionState() tls.ConnectionState {
	if c.conn == nil {
		return tls.ConnectionState{}
	}
	return c.conn.ConnectionState()
}
func (c *lazyClient) SetTransportParameters(b []byte) {
	c.params = append([]byte{}, b...)
	if c.conn != nil {
		c.conn.SetTransportParameters(b)
	}
}
