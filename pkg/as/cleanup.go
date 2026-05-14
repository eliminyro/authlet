package as

import (
	"context"
	"time"
)

// RunCleanup periodically purges expired auth codes, refresh tokens, and
// idle DCR clients. It also retires the in-memory authorize state map.
// Blocks until ctx is canceled.
func (a *AS) RunCleanup(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			_, _ = a.cfg.Storage.Codes().DeleteExpired(ctx, now)
			_, _ = a.cfg.Storage.RefreshTokens().DeleteExpired(ctx, now)
			_, _ = a.cfg.Storage.Clients().DeleteExpired(ctx, now.Add(-a.cfg.ClientTTL))
			a.states.GC(now)
			_ = a.cfg.KeyManager.RotateIfDue(ctx)
		}
	}
}
