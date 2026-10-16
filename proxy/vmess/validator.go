package vmess

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess/aead"
)

// TimedUserValidator is a user Validator based on time.
type TimedUserValidator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool

	aeadDecoderHolder *aead.AuthIDDecoderHolder
	legacyIDs         int
	legacyIndex       map[[16]byte]legacyTicket
	legacyEpoch       int64
	legacySessions    map[[48]byte]time.Time
	legacyNow         func() time.Time
}

// NewTimedUserValidator creates a new TimedUserValidator.
func NewTimedUserValidator() *TimedUserValidator {
	tuv := &TimedUserValidator{
		users:             make([]*protocol.MemoryUser, 0, 16),
		aeadDecoderHolder: aead.NewAuthIDDecoderHolder(),
		legacyNow:         time.Now,
	}
	return tuv
}

func (v *TimedUserValidator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	if u == nil {
		return errors.New("user is nil")
	}
	account, ok := u.Account.(*MemoryAccount)
	if !ok || account == nil || account.ID == nil {
		return errors.New("account type is incorrect")
	}
	if len(account.AlterIDs) > MaxLegacyAlterIDs {
		return errors.New("legacy VMess alterId exceeds 64")
	}
	ids := 0
	if len(account.AlterIDs) != 0 {
		ids = len(account.AlterIDs) + 1
	}
	if v.legacyIDs+ids > maxLegacyValidatorIDs {
		return errors.New("legacy VMess validator exceeds 256 IDs")
	}
	// Reject ambiguous legacy identities rather than choosing a user by map order.
	if ids != 0 || v.legacyIDs != 0 {
		for _, existing := range v.users {
			other := existing.Account.(*MemoryAccount)
			if ids == 0 && len(other.AlterIDs) == 0 {
				continue
			}
			for _, left := range append([]*protocol.ID{account.ID}, account.AlterIDs...) {
				for _, right := range append([]*protocol.ID{other.ID}, other.AlterIDs...) {
					if left == nil || right == nil || left.Equals(right) {
						return errors.New("overlapping legacy VMess identities")
					}
				}
			}
		}
	}
	for _, id := range account.AlterIDs {
		if id == nil {
			return errors.New("invalid legacy VMess ID")
		}
	}
	v.users = append(v.users, u)
	v.legacyIDs += ids
	v.legacyIndex = nil
	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("VMESSBSKDF"))
		hashkdf.Write(account.ID.Bytes())
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	var cmdkeyfl [16]byte
	copy(cmdkeyfl[:], account.ID.CmdKey())
	v.aeadDecoderHolder.AddUser(cmdkeyfl, u)

	return nil
}

func (v *TimedUserValidator) GetUsers() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

func (v *TimedUserValidator) GetCount() int64 {
	v.Lock()
	defer v.Unlock()
	return int64(len(v.users))
}

func (v *TimedUserValidator) GetAEAD(userHash []byte) (*protocol.MemoryUser, bool, error) {
	v.RLock()
	defer v.RUnlock()

	var userHashFL [16]byte
	copy(userHashFL[:], userHash)

	userd, err := v.aeadDecoderHolder.Match(userHashFL)
	if err != nil {
		return nil, false, err
	}
	return userd.(*protocol.MemoryUser), true, nil
}

func (v *TimedUserValidator) Remove(email string) bool {
	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	idx := -1
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			var cmdkeyfl [16]byte
			copy(cmdkeyfl[:], u.Account.(*MemoryAccount).ID.CmdKey())
			v.aeadDecoderHolder.RemoveUser(cmdkeyfl)
			account := u.Account.(*MemoryAccount)
			if len(account.AlterIDs) != 0 {
				v.legacyIDs -= len(account.AlterIDs) + 1
			}
			v.legacyIndex = nil
			break
		}
	}
	if idx == -1 {
		return false
	}
	ulen := len(v.users)

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]

	return true
}

func (v *TimedUserValidator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}

var ErrNotFound = errors.New("Not Found")

var ErrTainted = errors.New("ErrTainted")
