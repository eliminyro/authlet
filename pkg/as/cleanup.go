package as

import (
	"context"
	"time"
)

// RunCleanup starts the periodic cleanup loop in a background goroutine
// and returns a channel that closes when the goroutine exits after ctx
// is canceled. The loop purges expired auth codes, refresh tokens, and
// idle DCR clients, retires the in-memory authorize state map, and
// rotates the signing key when RotationInterval has elapsed.
//
// Callers that want to wait for a clean exit on shutdown can select on
// the returned channel; callers that don't care can simply discard it.
//
// API note: prior versions returned no value and were invoked as
// `go server.RunCleanup(ctx, dur)`. Existing call-sites still compile
// because the new return value is silently discarded.
func (a *AS) RunCleanup(ctx context.Context, every time.Duration) <-chan struct{} {
	done := make(chan struct{})
	if every <= 0 {
		every = time.Hour
	}
	go func() {
		defer close(done)
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
	}()
	return done
}
