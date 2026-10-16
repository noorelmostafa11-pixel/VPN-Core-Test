package vmess

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

const (
	MaxLegacyAlterIDs     = 64
	maxLegacyValidatorIDs = 256
	maxLegacySessions     = 8192
)

func newLegacyAlterIDs(primary *protocol.ID, count uint32) []*protocol.ID {
	ids := make([]*protocol.ID, 0, count)
	previous := primary.UUID()
	for range count {
		material := append(previous.Bytes(), []byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81")...)
		next := md5.Sum(material)
		for next == [16]byte(previous) {
			material = append(material, []byte("533eff8a-4113-4b10-b5ce-0f5d76b98cd2")...)
			next = md5.Sum(material)
		}
		previous = uuid.UUID(next)
		ids = append(ids, protocol.NewID(previous))
	}
	return ids
}

// LegacyAuthID is the historical HMAC-MD5 timestamp token, not an AEAD AuthID.
func LegacyAuthID(id []byte, timestamp int64) [16]byte {
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(timestamp))
	h := hmac.New(md5.New, id)
	h.Write(stamp[:])
	var token [16]byte
	copy(token[:], h.Sum(nil))
	return token
}

func LegacyHeaderIV(timestamp int64) [16]byte {
	var repeated [32]byte
	for i := 0; i < len(repeated); i += 8 {
		binary.BigEndian.PutUint64(repeated[i:i+8], uint64(timestamp))
	}
	return md5.Sum(repeated[:])
}

type legacyTicket struct {
	user  *protocol.MemoryUser
	stamp int64
}

// GetLegacy uses a bounded, lazily refreshed index. No background timer or
// per-connection scan of timestamps is introduced for modern-only validators.
func (v *TimedUserValidator) GetLegacy(token [16]byte) (*protocol.MemoryUser, int64, error) {
	v.Lock()
	defer v.Unlock()
	if v.legacyIDs == 0 {
		return nil, 0, ErrNotFound
	}
	now := v.legacyNow().Unix()
	if v.legacyIndex == nil || v.legacyEpoch != now/10 {
		index := make(map[[16]byte]legacyTicket, v.legacyIDs*261)
		base := now / 10 * 10
		for _, user := range v.users {
			account := user.Account.(*MemoryAccount)
			if len(account.AlterIDs) == 0 {
				continue
			}
			for _, id := range append([]*protocol.ID{account.ID}, account.AlterIDs...) {
				for stamp := base - 130; stamp <= base+130; stamp++ {
					index[LegacyAuthID(id.Bytes(), stamp)] = legacyTicket{user, stamp}
				}
			}
		}
		v.legacyIndex, v.legacyEpoch = index, now/10
	}
	ticket, found := v.legacyIndex[token]
	if !found || ticket.stamp < now-120 || ticket.stamp > now+120 {
		return nil, 0, ErrNotFound
	}
	return ticket.user, ticket.stamp, nil
}

// AcceptLegacySession runs only after the complete plaintext header is checked.
// A timestamp token may legitimately be shared by concurrent connections in one
// second. Replay protection must instead bind the primary user + body key + IV.
func (v *TimedUserValidator) AcceptLegacySession(user *protocol.MemoryUser, key, iv [16]byte) error {
	v.Lock()
	defer v.Unlock()
	present := false
	for _, candidate := range v.users {
		if candidate == user && len(candidate.Account.(*MemoryAccount).AlterIDs) != 0 {
			present = true
			break
		}
	}
	if !present {
		return ErrNotFound
	}
	var session [48]byte
	copy(session[:16], user.Account.(*MemoryAccount).ID.Bytes())
	copy(session[16:32], key[:])
	copy(session[32:], iv[:])
	now := v.legacyNow()
	if expires, exists := v.legacySessions[session]; exists && expires.After(now) {
		return errors.New("replayed legacy VMess session")
	}
	if len(v.legacySessions) >= maxLegacySessions {
		for id, expires := range v.legacySessions {
			if !expires.After(now) {
				delete(v.legacySessions, id)
			}
		}
		if len(v.legacySessions) >= maxLegacySessions {
			return errors.New("legacy VMess replay cache is full")
		}
	}
	if v.legacySessions == nil {
		v.legacySessions = make(map[[48]byte]time.Time)
	}
	// Covers the full -120..+120 second authentication horizon, not just 3min.
	v.legacySessions[session] = now.Add(241 * time.Second)
	return nil
}
