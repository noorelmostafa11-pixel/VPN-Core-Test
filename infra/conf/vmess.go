package conf

import (
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
	"google.golang.org/protobuf/proto"
)

type VMessAccount struct {
	ID             string               `json:"id"`
	Security       string               `json:"security"`
	Experiments    string               `json:"experiments"`
	LegacySettings *VMessLegacySettings `json:"legacySettings"`
}

// LegacySettings is a separate opt-in, not a reinterpretation of old ignored
// alterId/security fields. Original configurations keep upstream semantics.
type VMessLegacySettings struct {
	AlterID         uint32 `json:"alterId"`
	Security        string `json:"security"`
	AllowLegacyBody bool   `json:"allowLegacyBody"`
}

// Build implements Buildable
func (a *VMessAccount) Build() *vmess.Account {
	security := a.Security
	if a.LegacySettings != nil && a.LegacySettings.Security != "" {
		security = a.LegacySettings.Security
	}
	var st protocol.SecurityType
	switch strings.ToLower(security) {
	case "aes-128-gcm":
		st = protocol.SecurityType_AES128_GCM
	case "chacha20-poly1305":
		st = protocol.SecurityType_CHACHA20_POLY1305
	case "", "auto":
		st = protocol.SecurityType_AUTO
	default:
		st = protocol.SecurityType_AUTO
	}
	account := &vmess.Account{
		Id: a.ID,
		SecuritySettings: &protocol.SecurityConfig{
			Type: st,
		},
		TestsEnabled: a.Experiments,
	}
	if a.LegacySettings != nil {
		account.LegacyCompatibility = true
		account.AlterId = a.LegacySettings.AlterID
		account.AllowLegacyBody = a.LegacySettings.AllowLegacyBody
		switch strings.ToLower(security) {
		case "aes-128-cfb":
			account.SecuritySettings.Type = protocol.SecurityType_AES128_CFB
		case "none":
			account.SecuritySettings.Type = protocol.SecurityType_NONE
		case "zero":
			account.SecuritySettings.Type = protocol.SecurityType_ZERO
		case "", "auto", "aes-128-gcm", "chacha20-poly1305":
		default:
			account.SecuritySettings.Type = protocol.SecurityType_UNKNOWN
		}
	}
	return account
}

func (a *VMessAccount) validate() error {
	if a.LegacySettings == nil {
		return nil
	}
	if a.LegacySettings.AlterID > vmess.MaxLegacyAlterIDs {
		return errors.New("legacy VMess alterId exceeds 64")
	}
	if a.Build().SecuritySettings.Type == protocol.SecurityType_UNKNOWN {
		return errors.New("unsupported VMess security: ", a.Security)
	}
	security := a.Build().SecuritySettings.Type
	if (security == protocol.SecurityType_NONE || security == protocol.SecurityType_ZERO || security == protocol.SecurityType_AES128_CFB) && strings.Contains(a.Experiments, "AuthenticatedLength") {
		return errors.New("AuthenticatedLength requires an AEAD body mode")
	}
	return nil
}

type VMessDefaultConfig struct {
	Level byte `json:"level"`
}

// Build implements Buildable
func (c *VMessDefaultConfig) Build() *inbound.DefaultConfig {
	config := new(inbound.DefaultConfig)
	config.Level = uint32(c.Level)
	return config
}

type VMessInboundConfig struct {
	Users    []json.RawMessage   `json:"users"`
	Clients  []json.RawMessage   `json:"clients"`
	Defaults *VMessDefaultConfig `json:"default"`
}

// Build implements Buildable
func (c *VMessInboundConfig) Build() (proto.Message, error) {
	errors.PrintNonRemovalDeprecatedFeatureWarning("VMess (with no Forward Secrecy, etc.)", "VLESS Encryption")

	config := &inbound.Config{}

	if c.Defaults != nil {
		config.Default = c.Defaults.Build()
	}

	if c.Clients != nil {
		c.Users = c.Clients
	}
	config.User = make([]*protocol.User, len(c.Users))
	processUser := func(idx int) error {
		rawData := c.Users[idx]
		user := new(protocol.User)
		if err := json.Unmarshal(rawData, user); err != nil {
			return errors.New("invalid VMess user").Base(err)
		}
		account := new(VMessAccount)
		if err := json.Unmarshal(rawData, account); err != nil {
			return errors.New("invalid VMess user").Base(err)
		}

		u, err := uuid.ParseString(account.ID)
		if err != nil {
			return err
		}
		account.ID = u.String()
		if err := account.validate(); err != nil {
			return err
		}

		user.Account = serial.ToTypedMessage(account.Build())
		config.User[idx] = user
		return nil
	}
	if err := task.ParallelForN(len(c.Users), processUser); err != nil {
		return nil, err
	}

	return config, nil
}

type VMessOutboundTarget struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VMessOutboundConfig struct {
	LegacySettings *VMessLegacySettings   `json:"legacySettings"`
	Address        *Address               `json:"address"`
	Port           uint16                 `json:"port"`
	Level          uint32                 `json:"level"`
	Email          string                 `json:"email"`
	ID             string                 `json:"id"`
	Security       string                 `json:"security"`
	Experiments    string                 `json:"experiments"`
	Receivers      []*VMessOutboundTarget `json:"vnext"`
}

// Build implements Buildable
func (c *VMessOutboundConfig) Build() (proto.Message, error) {
	errors.PrintNonRemovalDeprecatedFeatureWarning("VMess (with no Forward Secrecy, etc.)", "VLESS Encryption")

	config := new(outbound.Config)
	if c.Address != nil {
		c.Receivers = []*VMessOutboundTarget{
			{
				Address: c.Address,
				Port:    c.Port,
				Users:   []json.RawMessage{{}},
			},
		}
	}
	if len(c.Receivers) != 1 {
		return nil, errors.New(`VMess settings: "vnext" should have one and only one member. Multiple endpoints in "vnext" should use multiple VMess outbounds and routing balancer instead`)
	}
	for _, rec := range c.Receivers {
		if len(rec.Users) != 1 {
			return nil, errors.New(`VMess vnext: "users" should have one and only one member. Multiple members in "users" should use multiple VMess outbounds and routing balancer instead`)
		}
		if rec.Address == nil {
			return nil, errors.New(`VMess vnext: "address" is not set`)
		}
		spec := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
		}
		for _, rawUser := range rec.Users {
			user := new(protocol.User)
			if c.Address != nil {
				user.Level = c.Level
				user.Email = c.Email
			} else {
				if err := json.Unmarshal(rawUser, user); err != nil {
					return nil, errors.New("invalid VMess user").Base(err)
				}
			}
			account := new(VMessAccount)
			if c.Address != nil {
				account.ID = c.ID
				account.LegacySettings = c.LegacySettings
				account.Security = c.Security
				account.Experiments = c.Experiments
			} else {
				if err := json.Unmarshal(rawUser, account); err != nil {
					return nil, errors.New("invalid VMess user").Base(err)
				}
			}

			u, err := uuid.ParseString(account.ID)
			if err != nil {
				return nil, err
			}
			account.ID = u.String()
			if err := account.validate(); err != nil {
				return nil, err
			}

			user.Account = serial.ToTypedMessage(account.Build())
			spec.User = user
			break
		}
		config.Receiver = spec
		break
	}
	return config, nil
}
