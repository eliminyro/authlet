package storage

import (
	"testing"
	"time"
)

func TestClientZeroValue(t *testing.T) {
	c := Client{}
	if c.ClientID != "" || len(c.RedirectURIs) != 0 || c.TokenEndpointAuthMethod != "" || len(c.SecretHash) != 0 {
		t.Fatalf("expected zero Client, got %+v", c)
	}
}

func TestSigningKeyActiveAndRetires(t *testing.T) {
	now := time.Now()
	retire := now.Add(24 * time.Hour)
	sk := SigningKey{ID: "k1", Algorithm: "RS256", IsActive: true, CreatedAt: now, RetiresAt: &retire}
	if !sk.IsActive {
		t.Fatal("expected IsActive=true")
	}
	if sk.RetiresAt == nil || !sk.RetiresAt.Equal(retire) {
		t.Fatalf("retires mismatch")
	}
}
