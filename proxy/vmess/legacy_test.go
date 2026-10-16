package vmess

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

func legacyUser(t *testing.T, number int, count uint32) *protocol.MemoryUser {
	t.Helper()
	account, err := (&Account{Id: fmt.Sprintf("00000000-0000-4000-8000-%012d", number), AlterId: count}).AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.MemoryUser{Email: fmt.Sprint(number), Account: account}
}

func TestForkVMessAlterIDDerivationAndRoundTrip(t *testing.T) {
	for _, count := range []uint32{0, 1, 16, 64} {
		u := legacyUser(t, 1, count)
		a := u.Account.(*MemoryAccount)
		prior := append([]byte(nil), a.ID.Bytes()...)
		for _, id := range a.AlterIDs {
			// Independent byte-level derivation, not the production helper.
			next := md5.Sum(append(prior, []byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81")...))
			if string(id.Bytes()) != string(next[:]) {
				t.Fatal("alter ID chain mismatch")
			}
			prior = append([]byte(nil), next[:]...)
		}
		if len(a.AlterIDs) != int(count) || a.ToProto().(*Account).AlterId != count || a.AllowLegacyBody {
			t.Fatal("alter count or independent body policy lost")
		}
		copy, err := a.ToProto().(*Account).AsAccount()
		if err != nil || !a.Equals(copy) || len(copy.(*MemoryAccount).AlterIDs) != int(count) {
			t.Fatal("account round trip failed", err)
		}
	}
	for _, count := range []uint32{65, ^uint32(0)} {
		if _, err := (&Account{Id: "00000000-0000-4000-8000-000000000001", AlterId: count}).AsAccount(); err == nil {
			t.Fatal("unbounded derivation accepted")
		}
	}
}

func TestForkVMessLegacyTimestampIndex(t *testing.T) {
	v := NewTimedUserValidator()
	now := time.Unix(1800000009, 0)
	v.legacyNow = func() time.Time { return now }
	u := legacyUser(t, 1, 64)
	if err := v.Add(u); err != nil {
		t.Fatal(err)
	}
	a := u.Account.(*MemoryAccount)
	for _, id := range append([]*protocol.ID{a.ID}, a.AlterIDs...) {
		for _, delta := range []int64{-121, -120, 0, 120, 121} {
			stamp := now.Unix() + delta
			var raw [8]byte
			binary.BigEndian.PutUint64(raw[:], uint64(stamp))
			h := hmac.New(md5.New, id.Bytes())
			h.Write(raw[:])
			var token [16]byte
			copy(token[:], h.Sum(nil))
			found, gotStamp, err := v.GetLegacy(token)
			if (err == nil) != (delta >= -120 && delta <= 120) {
				t.Fatal("timestamp boundary mismatch", delta, err)
			}
			if err == nil && (found != u || gotStamp != stamp) {
				t.Fatal("wrong user/timestamp")
			}
			if token != LegacyAuthID(id.Bytes(), stamp) {
				t.Fatal("HMAC wire mismatch")
			}
			var repeated []byte
			for range 4 {
				repeated = append(repeated, raw[:]...)
			}
			if LegacyHeaderIV(stamp) != md5.Sum(repeated) {
				t.Fatal("header IV mismatch")
			}
		}
	}
	if len(v.legacyIndex) != 65*261 {
		t.Fatal("unexpected index size", len(v.legacyIndex))
	}
	now = now.Add(time.Second)
	if _, _, err := v.GetLegacy(LegacyAuthID(a.AlterIDs[63].Bytes(), now.Unix()+120)); err != nil || v.legacyEpoch != now.Unix()/10 {
		t.Fatal("lazy epoch refresh failed", err)
	}
	if !v.Remove(u.Email) || v.legacyIDs != 0 || v.legacyIndex != nil {
		t.Fatal("remove did not invalidate index")
	}
	if _, _, err := v.GetLegacy(LegacyAuthID(a.ID.Bytes(), now.Unix())); err == nil {
		t.Fatal("removed user accepted")
	}
	if err := v.Add(legacyUser(t, 2, 0)); err != nil {
		t.Fatal(err)
	}
	v.GetLegacy([16]byte{})
	if v.legacyIndex != nil || v.legacySessions != nil {
		t.Fatal("modern-only validator allocated legacy state")
	}
}

func TestForkVMessLegacyValidatorLimits(t *testing.T) {
	v := NewTimedUserValidator()
	for i, count := range []uint32{64, 64, 64, 60} {
		if err := v.Add(legacyUser(t, i+1, count)); err != nil {
			t.Fatal(err)
		}
	}
	if v.legacyIDs != 256 || v.Add(legacyUser(t, 5, 1)) == nil || v.GetCount() != 4 {
		t.Fatal("ID bound not atomic")
	}
	user := v.users[0]
	if _, _, err := v.GetLegacy(LegacyAuthID(user.Account.(*MemoryAccount).ID.Bytes(), time.Now().Unix())); err != nil || len(v.legacyIndex) != 256*261 {
		t.Fatal("maximum bounded index mismatch", err, len(v.legacyIndex))
	}
	if err := v.Add(legacyUser(t, 6, 0)); err != nil {
		t.Fatal("legacy cap incorrectly limits modern users", err)
	}
	if !v.Remove("4") || v.Add(legacyUser(t, 5, 1)) != nil {
		t.Fatal("removed IDs were not released")
	}
	if v.Add(legacyUser(t, 1, 0)) == nil || v.Add(nil) == nil || v.Add(&protocol.MemoryUser{}) == nil || v.GetCount() != 5 {
		t.Fatal("invalid addition mutated validator")
	}
	// A modern account's primary ID may not overlap a legacy-derived identity,
	// in either insertion order; this would make a token's user ambiguous.
	for _, reverse := range []bool{false, true} {
		validator := NewTimedUserValidator()
		legacy := legacyUser(t, 7, 1)
		modern := &protocol.MemoryUser{Account: &MemoryAccount{ID: legacy.Account.(*MemoryAccount).AlterIDs[0]}}
		first, second := legacy, modern
		if reverse {
			first, second = second, first
		}
		if validator.Add(first) != nil || validator.Add(second) == nil || validator.GetCount() != 1 {
			t.Fatal("derived identity collision accepted", reverse)
		}
	}
}

func TestForkVMessLegacyReplayHorizonAndCapacity(t *testing.T) {
	v := NewTimedUserValidator()
	now := time.Unix(1800000000, 0)
	v.legacyNow = func() time.Time { return now }
	u := legacyUser(t, 1, 1)
	if err := v.Add(u); err != nil {
		t.Fatal(err)
	}
	var key, iv [16]byte
	if err := v.AcceptLegacySession(u, key, iv); err != nil {
		t.Fatal(err)
	}
	now = now.Add(240 * time.Second)
	if v.AcceptLegacySession(u, key, iv) == nil {
		t.Fatal("replay admitted during full authentication horizon")
	}
	now = now.Add(time.Second)
	if err := v.AcceptLegacySession(u, key, iv); err != nil {
		t.Fatal("expired cache entry not reusable", err)
	}
	for i := 1; i < maxLegacySessions; i++ {
		binary.BigEndian.PutUint64(key[:8], uint64(i))
		if err := v.AcceptLegacySession(u, key, iv); err != nil {
			t.Fatal(err)
		}
	}
	binary.BigEndian.PutUint64(key[:8], maxLegacySessions)
	if v.AcceptLegacySession(u, key, iv) == nil || len(v.legacySessions) != maxLegacySessions {
		t.Fatal("full replay cache did not fail closed")
	}
	now = now.Add(241 * time.Second)
	if err := v.AcceptLegacySession(u, key, iv); err != nil || len(v.legacySessions) != 1 {
		t.Fatal("capacity cleanup failed", err)
	}
	v.Remove(u.Email)
	if v.AcceptLegacySession(u, key, iv) == nil {
		t.Fatal("removed user finalized a request")
	}
	if err := v.Add(u); err != nil || v.AcceptLegacySession(u, key, iv) == nil {
		t.Fatal("remove/add bypassed retained replay history", err)
	}
}

func TestForkVMessLegacyValidatorConcurrent(t *testing.T) {
	v := NewTimedUserValidator()
	u := legacyUser(t, 1, 1)
	if err := v.Add(u); err != nil {
		t.Fatal(err)
	}
	token := LegacyAuthID(u.Account.(*MemoryAccount).AlterIDs[0].Bytes(), time.Now().Unix())
	var workers sync.WaitGroup
	for i := range 32 {
		workers.Go(func() {
			var key [16]byte
			binary.BigEndian.PutUint64(key[:8], uint64(i))
			if user, _, err := v.GetLegacy(token); err != nil || user != u {
				t.Error("concurrent shared timestamp failed", err)
			}
			if err := v.AcceptLegacySession(u, key, [16]byte{}); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	other := legacyUser(t, 2, 1)
	workers.Go(func() {
		for range 16 {
			if err := v.Add(other); err != nil {
				t.Error(err)
			}
			if !v.Remove(other.Email) {
				t.Error("concurrent remove failed")
			}
		}
	})
	workers.Go(func() {
		for range 32 {
			if _, _, err := v.GetLegacy(token); err != nil {
				t.Error(err)
			}
			v.GetUsers()
		}
	})
	workers.Wait()
}
