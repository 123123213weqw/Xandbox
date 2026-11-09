//go:build !linux

package nodecontrol

func NewPinnedClient(string, int) (*PinnedClient, error) { return nil, ErrProcessPin }
func NewProcessWatch(int) (*ProcessWatch, error)         { return nil, ErrProcessPin }
