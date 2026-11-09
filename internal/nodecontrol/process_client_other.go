//go:build !linux

package nodecontrol

func NewPinnedClient(string, int) (*PinnedClient, error) { return nil, ErrProcessPin }
