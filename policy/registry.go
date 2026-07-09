package policy

import (
	"container/list"
	"errors"
	"fmt"
	"sync"
	"time"

	"zerotrust-forward-proxy/auth"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

var (
	ErrPolicyNotFound    = errors.New("tenant policy not found")
	ErrPolicyLoadTimeout = errors.New("tenant policy load timeout")
)

// RegistryConfig tunes multi-tenant policy caching and loading.
type RegistryConfig struct {
	PolicyDir              string
	CacheSize              int
	LoadWorkers            int
	LoadTimeout            time.Duration
	DefaultDenyOnLoadFail  bool
}

func (c RegistryConfig) withDefaults() RegistryConfig {
	if c.CacheSize <= 0 {
		c.CacheSize = 500
	}
	if c.LoadWorkers <= 0 {
		c.LoadWorkers = 4
	}
	if c.LoadTimeout <= 0 {
		c.LoadTimeout = 5 * time.Second
	}
	return c
}

type cacheEntry struct {
	tenantID int64
	policy   *TenantPolicy
}

// TenantPolicyRegistry is the runtime index: tenant_id → *TenantPolicy (which contains ASTMap).
//
// # Runtime lookup (every HTTP request)
//
//   HTTP request
//     → JWT in Authorization / Proxy-Authorization
//     → auth.JWTValidator resolves tenant_id (claim or default_tenant in dev mode)
//     → proxy.evaluate() calls Policy.Decide(tenantID, domain, method)
//     → TenantPolicyRegistry.TenantPolicyFor(tenantID)
//           ├─ cache HIT:  return *TenantPolicy from cache[tenantID]  → tp.ast.ASTMap
//           └─ cache MISS: LoadFromDB(/var/ztfp/policies/{tenantID}/policy.db) → insert → return
//     → tp.Decide(domain, method) walks that tenant's ASTMap only
//
// # What we store (two maps)
//
//   cache map[int64]*list.Element     ← tenant_id → LRU list node
//        └─ cacheEntry { tenantID, policy *TenantPolicy }
//                              └─ policy.ast.ASTMap  ← per-tenant AST (not shared)
//
// Tenants not in cache have no RAM entry; their policy.db stays on disk until a request
// or fsnotify reload triggers TenantPolicyFor / ReloadTenant.
type TenantPolicyRegistry struct {
	cfg    RegistryConfig
	logger *zap.SugaredLogger

	mu      sync.Mutex
	cache   map[int64]*list.Element
	lru     *list.List
	loadCh  chan loadJob
	group   singleflight.Group
	closed  bool
}

type loadJob struct {
	tenantID int64
	result   chan loadResult
}

type loadResult struct {
	policy *TenantPolicy
	err    error
}

// NewRegistry creates an empty registry; call Watch to enable fsnotify reloads.
func NewRegistry(cfg RegistryConfig, logger *zap.SugaredLogger) *TenantPolicyRegistry {
	cfg = cfg.withDefaults()
	r := &TenantPolicyRegistry{
		cfg:    cfg,
		logger: logger,
		cache:  make(map[int64]*list.Element),
		lru:    list.New(),
		loadCh: make(chan loadJob, cfg.CacheSize),
	}
	for i := 0; i < cfg.LoadWorkers; i++ {
		go r.loadWorker()
	}
	return r
}

// Decide implements Evaluator.
func (r *TenantPolicyRegistry) Decide(tenantID int64, domain, method string) (Action, string, error) {
	tp, err := r.TenantPolicyFor(tenantID)
	if err != nil {
		if r.cfg.DefaultDenyOnLoadFail {
			return ActionBlock, err.Error(), err
		}
		return ActionAllow, "", err
	}
	action, msg := tp.Decide(domain, method)
	return action, msg, nil
}

// TenantPolicyFor returns a cached TenantPolicy or cold-loads it.
func (r *TenantPolicyRegistry) TenantPolicyFor(tenantID int64) (*TenantPolicy, error) {
	if tenantID <= 0 {
		return nil, ErrPolicyNotFound
	}
	if tp := r.getCached(tenantID); tp != nil {
		return tp, nil
	}
	return r.loadTenant(tenantID)
}

func (r *TenantPolicyRegistry) getCached(tenantID int64) *TenantPolicy {
	r.mu.Lock()
	defer r.mu.Unlock()
	if el, ok := r.cache[tenantID]; ok {
		r.lru.MoveToFront(el)
		return el.Value.(*cacheEntry).policy
	}
	return nil
}

func (r *TenantPolicyRegistry) loadTenant(tenantID int64) (*TenantPolicy, error) {
	key := fmt.Sprintf("%d", tenantID)
	v, err, _ := r.group.Do(key, func() (interface{}, error) {
		if tp := r.getCached(tenantID); tp != nil {
			return tp, nil
		}
		resCh := make(chan loadResult, 1)
		job := loadJob{tenantID: tenantID, result: resCh}
		select {
		case r.loadCh <- job:
		default:
			// queue saturated — load inline on caller goroutine via worker path
			go func() { r.loadCh <- job }()
		}
		select {
		case res := <-resCh:
			return res.policy, res.err
		case <-time.After(r.cfg.LoadTimeout):
			return nil, ErrPolicyLoadTimeout
		}
	})
	if err != nil {
		return nil, err
	}
	return v.(*TenantPolicy), nil
}

func (r *TenantPolicyRegistry) loadWorker() {
	for job := range r.loadCh {
		tp, err := r.loadFromDisk(job.tenantID)
		if err == nil {
			r.insert(job.tenantID, tp)
		} else if r.logger != nil {
			r.logger.Warnw("tenant policy load failed", "tenant_id", job.tenantID, "error", err)
		}
		job.result <- loadResult{policy: tp, err: err}
	}
}

func (r *TenantPolicyRegistry) loadFromDisk(tenantID int64) (*TenantPolicy, error) {
	path := auth.TenantPolicyDBPath(r.cfg.PolicyDir, tenantID)
	if !auth.TenantPolicyExists(r.cfg.PolicyDir, tenantID) {
		return nil, ErrPolicyNotFound
	}
	return LoadFromDB(path, tenantID)
}

func (r *TenantPolicyRegistry) insert(tenantID int64, tp *TenantPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if el, ok := r.cache[tenantID]; ok {
		el.Value.(*cacheEntry).policy = tp
		r.lru.MoveToFront(el)
		return
	}
	el := r.lru.PushFront(&cacheEntry{tenantID: tenantID, policy: tp})
	r.cache[tenantID] = el
	for r.lru.Len() > r.cfg.CacheSize {
		back := r.lru.Back()
		if back == nil {
			break
		}
		entry := back.Value.(*cacheEntry)
		delete(r.cache, entry.tenantID)
		r.lru.Remove(back)
	}
}

// ReloadTenant loads policy.db from disk and swaps the cached TenantPolicy.
func (r *TenantPolicyRegistry) ReloadTenant(tenantID int64) error {
	next, err := r.loadFromDisk(tenantID)
	if err != nil {
		return err
	}
	r.mu.Lock()
	el, ok := r.cache[tenantID]
	r.mu.Unlock()
	if ok {
		el.Value.(*cacheEntry).policy.Swap(next)
		return nil
	}
	r.insert(tenantID, next)
	return nil
}

// CacheSize returns the number of tenant policies currently in the LRU.
func (r *TenantPolicyRegistry) CacheSize() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lru.Len()
}

// Close stops loader workers.
func (r *TenantPolicyRegistry) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.loadCh)
	r.mu.Unlock()
}

// legacyEngine wraps YAML Engine for Evaluator compatibility in tests.
type legacyEngine struct {
	*Engine
}

func (l *legacyEngine) Decide(_ int64, domain, method string) (Action, string, error) {
	a, m := l.Engine.Decide(domain, method)
	return a, m, nil
}

// LegacyEvaluator adapts a YAML Engine to Evaluator (ignores tenant_id).
func LegacyEvaluator(e *Engine) Evaluator {
	if e == nil {
		return nil
	}
	return &legacyEngine{Engine: e}
}
