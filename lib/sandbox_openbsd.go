// +build openbsd

package lib

func Sandbox() error {
	if err = unix.Unveil("/", "r"); err != nil {
		return err
	}
 	if err = unix.Unveil("/tmp", "rwc"); err != nil {
		return err
	}
	if err = unix.Pledge("stdio inet rpath wpath cpath", ""); err != nil {
		return err
	}

	return nil
}
