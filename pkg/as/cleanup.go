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
			if n, err := a.cfg.Storage.Codes().DeleteExpired(ctx, now); err != nil {
				a.cfg.Logger.Warn("cleanup: codes DeleteExpired failed", "err", err)
			} else {
				a.cfg.Logger.Debug("cleanup: codes swept", "deleted", n)
			}
			if n, err := a.cfg.Storage.RefreshTokens().DeleteExpired(ctx, now); err != nil {
				a.cfg.Logger.Warn("cleanup: refresh DeleteExpired failed", "err", err)
			} else {
				a.cfg.Logger.Debug("cleanup: refresh swept", "deleted", n)
			}
			if n, err := a.cfg.Storage.Clients().DeleteExpired(ctx, now.Add(-a.cfg.ClientTTL)); err != nil {
				a.cfg.Logger.Warn("cleanup: clients DeleteExpired failed", "err", err)
			} else {
				a.cfg.Logger.Debug("cleanup: clients swept", "deleted", n)
			}
			a.states.GC(now)
			if err := a.cfg.KeyManager.RotateIfDue(ctx); err != nil {
				a.cfg.Logger.Warn("cleanup: key rotation failed", "err", err)
			}
		}
	}
}
