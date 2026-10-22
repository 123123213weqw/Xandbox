//go:build !linux

package firecracker

import (
	"context"
	"errors"
)

func SnapshotHostABI() (string, error) { return "", errors.New("snapshot ABI requires Linux/amd64") }

type SnapshotCatalog struct{}

func OpenSnapshotCatalog(string, string) (*SnapshotCatalog, error) {
	return nil, errors.New("snapshot administration requires Linux root")
}
func (*SnapshotCatalog) Publish(context.Context, string, string, string) (string, error) {
	return "", errors.New("snapshot administration requires Linux")
}
func (*SnapshotCatalog) Activate(context.Context, string) error {
	return errors.New("snapshot administration requires Linux")
}
func (*SnapshotCatalog) Retire(context.Context, string) error {
	return errors.New("snapshot administration requires Linux")
}
func (*SnapshotCatalog) Collect(context.Context) ([]string, error) {
	return nil, errors.New("snapshot administration requires Linux")
}
func (*SnapshotCatalog) Status(context.Context) (CatalogStatus, error) {
	return CatalogStatus{}, errors.New("snapshot administration requires Linux")
}

func OpenSnapshotCatalogContext(context.Context, string, string) (*SnapshotCatalog, error) {
	return nil, errors.New("snapshot administration requires Linux root")
}
