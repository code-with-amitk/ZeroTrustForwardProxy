package policy

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch a directory continuously. Whenever a tenant's policy.db file changes, reload that tenant's policy.
func (r *TenantPolicyRegistry) Watch(ctx context.Context) error {

	// This creates an OS filesystem watcher. Whenever a file changes, the watcher receives an event.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := watcher.Add(r.cfg.PolicyDir); err != nil {
		_ = watcher.Close()
		return err
	}
	if r.logger != nil {
		r.logger.Infow("tenant policy watcher started", "dir", r.cfg.PolicyDir)
	}

	// Creates a mutex, which will protect pending hashmap(since these are NOT thread-safe). key=tenantid, value=timer.
	// Multiple goroutines may access this map.
	var mu sync.Mutex
	pending := make(map[int64]*time.Timer)

	// lambda captures env variables. Capture mu, r, pending
	schedule := func(tenantID int64) {

		// https://code-with-amitk.github.io/Languages/Programming/Go/
		// defer will always unlock the mutex, no matter function returns from error or not.
		mu.Lock()
		defer mu.Unlock()

		// debouncing
		// If the same tenant's policy.db file is changed multiple times within 300ms, only the last change will be processed.
		if t, ok := pending[tenantID]; ok {
			t.Stop()
		}
		// func time.AfterFunc(d time.Duration, f func()) *time.Timer
		// After 300ms function is called and returns a timer which is stored in pending map.
		pending[tenantID] = time.AfterFunc(300*time.Millisecond, func() {
			mu.Lock()
			// delete entry from map after timer expires and we read it successfully
			delete(pending, tenantID)
			mu.Unlock()
			if err := r.ReloadTenant(tenantID); err != nil {
				if r.logger != nil {
					r.logger.Warnw("policy reload failed", "tenant_id", tenantID, "error", err)
				}
			} else if r.logger != nil {
				r.logger.Infow("tenant policy reloaded", "tenant_id", tenantID)
			}
		})
	}

	// Start 1 go routine
	go func() {
		defer watcher.Close()
		for { //infinite loop, runs until context cancelled or watcher.Close() is called
			select {
			case <-ctx.Done():
				// context cancelled, stop all timers and return
				mu.Lock()
				for _, t := range pending {
					t.Stop()
				}
				mu.Unlock()
				return
			case event, ok := <-watcher.Events:
				// file watcher events.
				if !ok {
					return
				}
				if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) && !event.Has(fsnotify.Rename) {
					continue
				}
				if !strings.HasSuffix(filepath.Base(event.Name), "policy.db") {
					// watch new tenant directories
					if event.Has(fsnotify.Create) {
						_ = watcher.Add(event.Name)
					}
					continue
				}
				tenantID := tenantIDFromPath(r.cfg.PolicyDir, event.Name)
				if tenantID > 0 {
					schedule(tenantID)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				if r.logger != nil {
					r.logger.Warnw("policy watcher error", "error", err)
				}
			}
		}
	}()
	return nil
}

// Since policy.db is stored in /var/ztfp/policies/{tenantid}/policy.db
// we can to extract the tenantid from the event path.
func tenantIDFromPath(policyRoot, eventPath string) int64 {
	rel, err := filepath.Rel(policyRoot, eventPath)
	if err != nil {
		return 0
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 2 {
		return 0
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}
