package gleam

import (
	"fmt"
	"syscall"
	"time"
)

type errno struct {
	proc string
	num  uintptr
}

func (e *errno) Error() string {
	return fmt.Sprintf("RuntimeM.%s return errno: 0x%08X", e.proc, e.num)
}

// RuntimeOpts contains options about initialize runtime.
type RuntimeOpts struct {
	BootInstAddress     uintptr `toml:"boot_inst_address" json:"boot_inst_address"`
	NotEraseInstruction bool    `toml:"not_erase_instruction" json:"not_erase_instruction"`
	NotAdjustProtect    bool    `toml:"not_adjust_protect" json:"not_adjust_protect"`
	TrackCurrentThread  bool    `toml:"track_current_thread" json:"track_current_thread"`
}

// RuntimeM contains exported runtime methods.
type RuntimeM struct {
	HashAPI struct {
		FindAPI  uintptr
		FindAPIA uintptr
		FindAPIW uintptr
	}

	Library struct {
		LoadA   uintptr
		LoadW   uintptr
		LoadExA uintptr
		LoadExW uintptr
		Free    uintptr
		GetProc uintptr
	}

	Memory struct {
		Alloc   uintptr
		Calloc  uintptr
		Realloc uintptr
		Free    uintptr
	}

	Thread struct {
		New   uintptr
		Exit  uintptr
		Sleep uintptr
	}

	Argument struct {
		GetValue   uintptr
		GetPointer uintptr
		Erase      uintptr
		EraseAll   uintptr
	}

	WinBase struct {
		ANSIToUTF16  uintptr
		UTF16ToANSI  uintptr
		ANSIToUTF16N uintptr
		UTF16ToANSIN uintptr
	}

	WinFile struct {
		ReadFileA  uintptr
		ReadFileW  uintptr
		WriteFileA uintptr
		WriteFileW uintptr
	}

	WinHTTP struct {
		Get  uintptr
		Post uintptr
		Do   uintptr
	}

	Random struct {
		Buffer  uintptr
		Bool    uintptr
		Int64   uintptr
		Uint64  uintptr
		Int64N  uintptr
		Uint64N uintptr
	}

	Crypto struct {
		Encrypt uintptr
		Decrypt uintptr
	}

	Compressor struct {
		Compress   uintptr
		Decompress uintptr
	}

	IAT struct {
		GetProcByName   uintptr
		GetProcByHash   uintptr
		GetProcOriginal uintptr
	}

	Core struct {
		Sleep   uintptr
		Hide    uintptr
		Recover uintptr
		Exit    uintptr
	}
}

// Sleep is used to sleep and hide runtime.
func (rt *RuntimeM) Sleep(d time.Duration) error {
	ms := uintptr(d.Milliseconds())
	ret, _, _ := syscall.SyscallN(rt.Core.Sleep, ms)
	if ret == 0 {
		return nil
	}
	return &errno{proc: "Core.Sleep", num: ret}
}

// Exit is used to exit runtime.
func (rt *RuntimeM) Exit() error {
	ret, _, _ := syscall.SyscallN(rt.Core.Exit)
	if ret == 0 {
		return nil
	}
	return &errno{proc: "Core.Exit", num: ret}
}
