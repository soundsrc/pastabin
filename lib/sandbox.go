//go:build !openbsd
// +build !openbsd

package lib

func Sandbox(socketPath string) error {
	return nil
}
