package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-trivy/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-trivy/pkg/job"
)

func TestStore_MissingScanJob(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	s := NewStore(etc.RedisStore{
		Namespace:  "harbor.scanner.trivy:data-store",
		ScanJobTTL: time.Hour,
	}, rdb)

	// The scan job TTL can elapse, or the key can be evicted, before the worker
	// finishes, and then Get returns no job and no error.
	scanJobKey := job.ScanJobKey{
		ID:       "expired-scan-job",
		MIMEType: api.MimeTypeSecurityVulnerabilityReport,
	}

	t.Run("UpdateStatus should return error when scan job is gone", func(t *testing.T) {
		assert.Error(t, s.UpdateStatus(context.Background(), scanJobKey, job.Finished))
	})

	t.Run("UpdateReport should return error when scan job is gone", func(t *testing.T) {
		assert.Error(t, s.UpdateReport(context.Background(), scanJobKey, harbor.ScanReport{}))
	})
}
