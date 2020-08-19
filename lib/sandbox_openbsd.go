// +build openbsd

package lib

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func Sandbox(socketPath string) error {
	var err error
	var exePath string

	if exePath, err = os.Executable(); err != nil {
		return err
	}

	exeDir := filepath.Dir(exePath)

	templateFiles := []string{ "main.gohtml", "header.gohtml", "footer.gohtml", "display.gohtml" }
	for _, file := range templateFiles {
		if err = unix.Unveil(filepath.Join(exeDir, file), "r"); err != nil {
			return err
		}
	}

	if err = unix.Unveil("/etc/resolv.conf", "r"); err != nil {
		return err
	}

	if err = unix.Unveil("/etc/hosts", "r"); err != nil {
		return err
	}

 	if err = unix.Unveil("/tmp", "rwc"); err != nil {
		return err
	}

	if socketPath != "" {
		if err = unix.Unveil(socketPath, "rwc"); err != nil {
			return err
        }
	}

	if err = unix.Pledge("stdio inet rpath wpath cpath", ""); err != nil {
		return err
	}

	return nil
}
