package jwt

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
	"github.com/eliminyro/authlet/pkg/storage/memstore"
)

func newManager(t *testing.T) (*Manager, *memstore.Store) {
	t.Helper()
	mk := make([]byte, 32)
	_, _ = rand.Read(mk)
	store := memstore.New()
	return NewManager(store.SigningKeys(), mk), store
}

func TestManager_BootstrapInsertsActiveKey(t *testing.T) {
	m, store := newManager(t)
	if err := m.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	keys, _ := store.SigningKeys().ListActive(context.Background())
	if len(keys) != 1 || !keys[0].IsActive {
		t.Fatalf("expected 1 active key, got %+v", keys)
	}
}

func TestManager_BootstrapIdempotent(t *testing.T) {
	m, store := newManager(t)
	_ = m.Bootstrap(context.Background())
	_ = m.Bootstrap(context.Background())
	keys, _ := store.SigningKeys().ListActive(context.Background())
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

func TestManager_SignerRoundTrip(t *testing.T) {
	m, _ := newManager(t)
	_ = m.Bootstrap(context.Background())
	priv, kid, err := m.Signer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if kid == "" || priv == nil {
		t.Fatal("expected non-empty signer")
	}
	// Sign a token, verify with the manager's PublicKeyFunc.
	tok, err := Sign(Claims{Issuer: "i", Subject: "s", Audience: "a", ExpiresAt: time.Now().Add(time.Hour).Unix()}, kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tok, m.PublicKeyFunc(context.Background()), VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestManager_RotateIfDue_NotDue(t *testing.T) {
	m, store := newManager(t)
	_ = m.Bootstrap(context.Background())
	_ = m.RotateIfDue(context.Background())
	keys, _ := store.SigningKeys().ListActive(context.Background())
	if len(keys) != 1 {
		t.Fatalf("expected 1 key (not yet due), got %d", len(keys))
	}
}

func TestManager_RotateIfDue_RotatesAfter30Days(t *testing.T) {
	m, store := newManager(t)
	t0 := time.Now()
	m.SetNow(func() time.Time { return t0 })
	_ = m.Bootstrap(context.Background())

	// Capture the original signer ID before rotation so we can assert which
	// key remains after the overlap window.
	original, err := store.SigningKeys().GetSigner(context.Background())
	if err != nil {
		t.Fatalf("get original signer: %v", err)
	}

	m.SetNow(func() time.Time { return t0.Add(31 * 24 * time.Hour) })
	if err := m.RotateIfDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Within the overlap window: both the retired old key and the new
	// signer must be visible via the Manager's clock-aware view.
	jwks, err := m.PublishJWKS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 active keys during 24h overlap, got %d", len(jwks.Keys))
	}
	signer, err := store.SigningKeys().GetSigner(context.Background())
	if err != nil {
		t.Fatalf("get new signer: %v", err)
	}
	if signer.ID == original.ID {
		t.Fatalf("expected new signer ID after rotation, still %q", signer.ID)
	}

	// Past the overlap window: only the new signer should remain visible.
	m.SetNow(func() time.Time { return t0.Add(31*24*time.Hour + 25*time.Hour) })
	jwks, err = m.PublishJWKS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected only the new signer post-overlap, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != signer.ID {
		t.Fatalf("expected remaining kid %q, got %q", signer.ID, jwks.Keys[0].Kid)
	}
}

func TestManager_PublishJWKS(t *testing.T) {
	m, _ := newManager(t)
	_ = m.Bootstrap(context.Background())
	jwks, err := m.PublishJWKS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 JWK, got %d", len(jwks.Keys))
	}
}

func TestManager_UnknownKIDFromCache(t *testing.T) {
	m, _ := newManager(t)
	_ = m.Bootstrap(context.Background())
	resolve := m.PublicKeyFunc(context.Background())
	if _, err := resolve("nonexistent"); err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

// TestManager_SetNowIsRaceFree exercises SetNow concurrently with
// PublishJWKS (which reads m.now) under -race to verify the mutex.
func TestManager_SetNowIsRaceFree(t *testing.T) {
	m, _ := newManager(t)
	_ = m.Bootstrap(context.Background())
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		t0 := time.Now()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				m.SetNow(func() time.Time { return t0.Add(time.Duration(i) * time.Second) })
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = m.PublishJWKS(context.Background())
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

var _ = storage.ErrNotFound // keep import
