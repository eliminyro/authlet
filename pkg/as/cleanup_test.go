package as

import (
	"context"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

func TestRunCleanup_PurgesExpiredCodes(t *testing.T) {
	a := newTestAS(t)
	_ = a.cfg.Storage.Codes().Save(context.Background(), storage.AuthCode{
		CodeHash:  "old",
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.RunCleanup(ctx, 50*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	cancel()
	n, _ := a.cfg.Storage.Codes().DeleteExpired(context.Background(), time.Now())
	if n != 0 {
		t.Fatalf("expected codes already gone, found %d still expired", n)
	}
}
