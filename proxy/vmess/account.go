package vmess

import (
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

// MemoryAccount is an in-memory form of VMess account.
type MemoryAccount struct {
	// ID is the main ID of the account.
	ID *protocol.ID
	// AlterIDs explicitly selects legacy timestamp/HMAC headers when nonempty.
	AlterIDs []*protocol.ID
	// Security type of the account. Used for client connections.
	Security            protocol.SecurityType
	AllowLegacyBody     bool
	LegacyCompatibility bool

	AuthenticatedLengthExperiment bool
	NoTerminationSignal           bool
}

// Equals implements protocol.Account.
func (a *MemoryAccount) Equals(account protocol.Account) bool {
	vmessAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.ID.Equals(vmessAccount.ID)
}

func (a *MemoryAccount) ToProto() proto.Message {
	test := ""
	if a.AuthenticatedLengthExperiment {
		test = "AuthenticatedLength|"
	}
	if a.NoTerminationSignal {
		test = test + "NoTerminationSignal"
	}
	return &Account{
		Id:                  a.ID.String(),
		AlterId:             uint32(len(a.AlterIDs)),
		TestsEnabled:        test,
		SecuritySettings:    &protocol.SecurityConfig{Type: a.Security},
		AllowLegacyBody:     a.AllowLegacyBody,
		LegacyCompatibility: a.LegacyCompatibility,
	}
}

// AsAccount implements protocol.Account.
func (a *Account) AsAccount() (protocol.Account, error) {
	security := a.SecuritySettings.GetSecurityType()
	if a.LegacyCompatibility {
		if a.AlterId > MaxLegacyAlterIDs {
			return nil, errors.New("legacy VMess alterId exceeds 64")
		}
		switch security {
		case protocol.SecurityType_AES128_CFB, protocol.SecurityType_NONE, protocol.SecurityType_ZERO:
			if strings.Contains(a.TestsEnabled, "AuthenticatedLength") {
				return nil, errors.New("AuthenticatedLength requires an AEAD body mode")
			}
		case protocol.SecurityType_AES128_GCM, protocol.SecurityType_CHACHA20_POLY1305:
		default:
			return nil, errors.New("unsupported VMess security type")
		}
	}
	id, err := uuid.ParseString(a.Id)
	if err != nil {
		return nil, errors.New("failed to parse ID").Base(err)
	}
	protoID := protocol.NewID(id)
	var AuthenticatedLength, NoTerminationSignal bool
	if strings.Contains(a.TestsEnabled, "AuthenticatedLength") {
		AuthenticatedLength = true
	}
	if strings.Contains(a.TestsEnabled, "NoTerminationSignal") {
		NoTerminationSignal = true
	}
	account := &MemoryAccount{
		ID:                            protoID,
		Security:                      security,
		LegacyCompatibility:           a.LegacyCompatibility,
		AuthenticatedLengthExperiment: AuthenticatedLength,
		NoTerminationSignal:           NoTerminationSignal,
	}
	if a.LegacyCompatibility {
		account.AlterIDs = newLegacyAlterIDs(protoID, a.AlterId)
		account.AllowLegacyBody = a.AllowLegacyBody
	}
	return account, nil
}
