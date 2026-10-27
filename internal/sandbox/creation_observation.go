package sandbox

import (
	"context"

	"github.com/123123213weqw/Xandbox/internal/telemetry"
)

// WithCreationTrace binds observations to the same registry as this manager's
// metrics. The sealed kind is selected by the handler, not tenant input.
// It does not admit work or change cancellation, deadlines or operation errors.
func (m *Manager) WithCreationTrace(ctx context.Context, kind telemetry.CreationKind) context.Context {
	if m == nil {
		return telemetry.WithCreationTrace(ctx)
	}
	return telemetry.WithCreationTraceKind(ctx, m.opts.Metrics, kind)
}
