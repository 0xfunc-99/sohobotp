//go:build !linux && !windows

package inventory

import "multiotp-portal/agent/internal/protocol"

func accounts() []protocol.Account { return nil }
