package main

import (
	"fmt"
	"log"
	"reflect"
	"syscall"
	"time"
	"unsafe"
	
	"golang.org/x/sys/windows"
)

var globalVar = 12345678

func main() {
	testWindowsAPI()
	
	localVar := 12121212
	
	do := func() {
		fmt.Println("Thread ID:", windows.GetCurrentThreadId())
		
		fmt.Printf("global variable pointer: 0x%X\n", &globalVar)
		fmt.Println("global variable value:  ", globalVar)
		
		fmt.Printf("local  variable pointer: 0x%X\n", &localVar)
		fmt.Println("local  variable value:  ", localVar)
		
		funcAddr := reflect.ValueOf(testWindowsAPI).Pointer()
		fmt.Printf("function instruction:      0x%X\n", funcAddr)
		
		inst := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), 8)
		fmt.Printf("function instruction data: %v\n", inst)
		
		time.Sleep(3 * time.Second)
		fmt.Println("finish!")
		fmt.Println()
	}
	
	for {
		do()
		sleep()
	}
}

func testWindowsAPI() {
	dll := windows.NewLazySystemDLL("kernel32.dll")
	hModule := windows.Handle(dll.Handle())
	GetProcAddress := dll.NewProc("GetProcAddress").Addr()
	fmt.Printf("GetProcAddress: 0x%X\n", GetProcAddress)
	
	for _, proc := range []string{
		"RT_GetProcAddressByName",
		"RT_GetProcAddressByHash",
		"RT_GetProcAddressOriginal",
	} {
		dllProcAddr := dll.NewProc(proc).Addr()
		getProcAddr, err := windows.GetProcAddress(hModule, proc)
		checkError(err)
		if dllProcAddr != getProcAddr {
			log.Fatalln("unexpected proc address")
		}
		fmt.Printf("%s: 0x%X\n", proc, dllProcAddr)
	}
	fmt.Println()
	
	GetProcAddressOriginal, err := windows.GetProcAddress(hModule, "RT_GetProcAddressOriginal")
	checkError(err)
	
	// get GetProcAddress
	proc, err := syscall.BytePtrFromString("GetProcAddress")
	checkError(err)
	ret, _, _ := syscall.SyscallN(
		GetProcAddressOriginal,
		uintptr(hModule), (uintptr)(unsafe.Pointer(proc)),
	)
	if ret == 0 {
		log.Fatalln("failed to get GetProcAddress address")
	}
	fmt.Printf("Hooked   GetProcAddress: 0x%X\n", GetProcAddress)
	fmt.Printf("Original GetProcAddress: 0x%X\n", ret)
	
	// get VirtualAlloc
	proc, err = syscall.BytePtrFromString("VirtualAlloc")
	checkError(err)
	ret, _, _ = syscall.SyscallN(
		GetProcAddressOriginal,
		uintptr(hModule), (uintptr)(unsafe.Pointer(proc)),
	)
	if ret == 0 {
		log.Fatalln("failed to get GetProcAddress address")
	}
	VirtualAlloc, err := windows.GetProcAddress(hModule, "VirtualAlloc")
	checkError(err)
	
	fmt.Printf("Hooked   VirtualAlloc: 0x%X\n", VirtualAlloc)
	fmt.Printf("Original VirtualAlloc: 0x%X\n", ret)
}

var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	procSleep   = modKernel32.NewProc("Sleep").Addr()
)

func sleep() {
	fmt.Println("call kernel32.Sleep [hooked]")
	now := time.Now()
	syscall.SyscallN(procSleep, uintptr(3000))
	fmt.Println("Sleep:", time.Since(now))
	fmt.Println()
}

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
