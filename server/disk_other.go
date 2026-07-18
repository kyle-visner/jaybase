//go:build !darwin && !linux

package server

import "fmt"

func diskAvailableBytes(path string) (uint64, error) {
	return 0, fmt.Errorf("free-space checks are not supported for %s on this platform", path)
}
