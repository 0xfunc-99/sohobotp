//go:build !linux && !windows

package inventory

import "multiotp-portal/agent/internal/protocol"

// platform: development builds (macOS) report the basics only.
func platform(*protocol.Inventory) {}
