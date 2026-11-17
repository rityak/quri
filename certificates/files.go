package certificates

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/tls"
)

// DefaultReloadInterval bounds certificate renewal detection without a watcher dependency.
const DefaultReloadInterval = 30 * time.Second

// Files publishes only complete certificate/key pairs, retaining the previous pair
// when an external issuer is partway through replacing the files.
type Files struct {
	certificatePath, keyPath string
	mu                       sync.Mutex
	current                  atomic.Pointer[tls.Certificate]
}

// LoadFiles validates the first pair before the listener can start.
func LoadFiles(certificatePath, keyPath string) (*Files, error) {
	f := &Files{certificatePath: certificatePath, keyPath: keyPath}
	if err := f.Reload(); err != nil {
		return nil, err
	}
	return f, nil
}

// Reload atomically replaces the TLS certificate only after validating both files.
func (f *Files) Reload() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	certificate, err := tls.LoadX509KeyPair(f.certificatePath, f.keyPath)
	if err != nil {
		return err
	}
	f.current.Store(&certificate)
	return nil
}

// GetCertificate is a tls.Config callback; established connections are unaffected.
func (f *Files) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return f.current.Load(), nil
}

// Run polls external certificate files until ctx ends. The caller owns this worker.
func (f *Files) Run(ctx context.Context, logger *slog.Logger) error {
	ticker := time.NewTicker(DefaultReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := f.Reload(); err != nil && logger != nil {
				logger.Warn("certificate reload failed; retaining previous certificate", "error", err)
			}
		}
	}
}
