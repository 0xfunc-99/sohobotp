//go:build windows

package agent

import (
	"bufio"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ownConsole: the console window was opened for this program (double-click in Explorer),
// so it closes with it.
func ownConsole() bool {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	var list [2]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&list[0])), 2)
	return n == 1
}

// PauseIfOwnConsole keeps the window of a double-clicked agent open until Enter.
func PauseIfOwnConsole() {
	if ownConsole() {
		fmt.Print("Press Enter to close this window. ")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
}

// RelaunchElevated starts this program again as administrator (the Windows consent prompt)
// when it is not elevated: an agent downloaded from the portal and double-clicked. true when
// the elevated copy was started and this one should exit.
func RelaunchElevated() bool {
	if windows.GetCurrentProcessToken().IsElevated() {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL) == nil
}
