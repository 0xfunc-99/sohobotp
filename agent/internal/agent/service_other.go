//go:build !linux && !windows

package agent

import "errors"

var errUnsupported = errors.New("the SohobOTP agent runs on Linux and Windows only")

func RequireAdmin() error     { return nil }
func InstallService() error   { return errUnsupported }
func UninstallService() error { return errUnsupported }
func RunService() error {
	stop := make(chan struct{})
	go func() { waitForSignal(); close(stop) }()
	_ = Serve(stop)
	return nil
}
