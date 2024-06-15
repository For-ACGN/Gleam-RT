package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"reflect"
	"syscall"
	"time"
	"unsafe"
)

var (
	modKernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGetCurrentThreadID = modKernel32.NewProc("GetCurrentThreadId")
	procSleep              = modKernel32.NewProc("Sleep")
)

func main() {
	testRuntimeAPI()
	testMemoryData()
	testGoRoutine()
	testLargeBuffer()
	testHTTPServer()
	testHTTPClient()
	kernel32Sleep()

	for {
		fmt.Println("keep alive")
		time.Sleep(250 * time.Millisecond)
	}
}

func testRuntimeAPI() {
	dll := syscall.NewLazyDLL("kernel32.dll")
	hModule := syscall.Handle(dll.Handle())
	GetProcAddress := dll.NewProc("GetProcAddress").Addr()
	fmt.Printf("GetProcAddress: 0x%X\n", GetProcAddress)

	for _, proc := range []string{
		"RT_GetProcAddressByName",
		"RT_GetProcAddressByHash",
		"RT_GetProcAddressOriginal",
	} {
		err := dll.NewProc(proc).Find()
		if err != nil {
			fmt.Println("[warning] failed to find runtime methods")
			return
		}
		dllProcAddr := dll.NewProc(proc).Addr()
		getProcAddr, err := syscall.GetProcAddress(hModule, proc)
		checkError(err)
		if dllProcAddr != getProcAddr {
			log.Fatalln("unexpected proc address")
		}
		fmt.Printf("%s: 0x%X\n", proc, dllProcAddr)
	}
	fmt.Println()

	GetProcAddressOriginal, err := syscall.GetProcAddress(hModule, "RT_GetProcAddressOriginal")
	checkError(err)

	// get original GetProcAddress
	proc, err := syscall.BytePtrFromString("GetProcAddress")
	checkError(err)
	ret, _, _ := syscall.SyscallN(
		GetProcAddressOriginal,
		uintptr(hModule), (uintptr)(unsafe.Pointer(proc)),
	)
	if ret == 0 {
		log.Fatalln("failed to get GetProcAddress address")
	}
	fmt.Printf("Original GetProcAddress: 0x%X\n", ret)
	fmt.Printf("Hooked   GetProcAddress: 0x%X\n", GetProcAddress)

	// get original VirtualAlloc
	proc, err = syscall.BytePtrFromString("VirtualAlloc")
	checkError(err)
	ret, _, _ = syscall.SyscallN(
		GetProcAddressOriginal,
		uintptr(hModule), (uintptr)(unsafe.Pointer(proc)),
	)
	if ret == 0 {
		log.Fatalln("failed to get GetProcAddress address")
	}

	VirtualAlloc, err := syscall.GetProcAddress(hModule, "VirtualAlloc")
	checkError(err)

	fmt.Printf("Original VirtualAlloc: 0x%X\n", ret)
	fmt.Printf("Hooked   VirtualAlloc: 0x%X\n", VirtualAlloc)
}

var globalVar = 12345678

func testMemoryData() {
	go func() {
		localVar := 12121212
		localStr := "hello GleamRT"

		for {
			tid, _, _ := procGetCurrentThreadID.Call()
			fmt.Println("Thread ID:", tid)

			fmt.Printf("global variable pointer: 0x%X\n", &globalVar)
			fmt.Println("global variable value:  ", globalVar)

			fmt.Printf("local variable pointer:  0x%X\n", &localVar)
			fmt.Println("local variable value:   ", localVar)

			funcAddr := reflect.ValueOf(testRuntimeAPI).Pointer()
			fmt.Printf("instruction:             0x%X\n", funcAddr)

			inst := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), 8)
			fmt.Printf("instruction data:        %v\n", inst)

			time.Sleep(time.Second)
			fmt.Println(localStr, "finish!")
			fmt.Println()
		}
	}()
}

func testGoRoutine() {
	ch := make(chan int, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		var i int
		for {
			select {
			case ch <- i:
			case <-ctx.Done():
				return
			}
			i++
			time.Sleep(50 * time.Millisecond)
		}
	}()
	go func() {
		// deadlock
		defer cancel()
		for {
			select {
			case i := <-ch:
				fmt.Println("index:", i)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func testLargeBuffer() {
	alloc := func(period time.Duration, min, max int) {
		for {
			buf := make([]byte, min+rand.Intn(max))
			init := byte(rand.Int())
			for i := 0; i < len(buf); i++ {
				buf[i] = init
				init++
			}
			fmt.Println("alloc buffer:", len(buf))

			// check memory data after trigger sleep
			raw := sha256.Sum256(buf)
			time.Sleep(250 * time.Millisecond)
			now := sha256.Sum256(buf)
			if raw != now {
				log.Fatalf("memory data is incorrect")
			}
			time.Sleep(period)
		}
	}
	go alloc(100*time.Millisecond, 1, 128)
	go alloc(100*time.Millisecond, 1, 512)
	go alloc(100*time.Millisecond, 256, 1024)
	go alloc(100*time.Millisecond, 512, 1024)
	go alloc(150*time.Millisecond, 1024, 16*1024)
	go alloc(150*time.Millisecond, 4096, 16*1024)
	go alloc(250*time.Millisecond, 16*1024, 512*1024)
	go alloc(250*time.Millisecond, 64*1024, 512*1024)
	go alloc(500*time.Millisecond, 1*1024*1024, 4*1024*1024)
	go alloc(500*time.Millisecond, 2*1024*1024, 4*1024*1024)
}

var (
	webAddr = "127.0.0.1:0"
	webPage = []byte("hello browser!")
)

func testHTTPServer() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	checkError(err)
	webAddr = listener.Addr().String()
	fmt.Println("web server:", webAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(webPage)
	})

	server := http.Server{
		Handler: mux,
	}
	go func() {
		err := server.Serve(listener)
		checkError(err)
	}()
}

func testHTTPClient() {
	go func() {
		client := http.Client{}
		for {
			func() {
				resp, err := client.Get(fmt.Sprintf("http://%s/", webAddr))
				checkError(err)
				defer func() { _ = resp.Body.Close() }()
				data, err := io.ReadAll(resp.Body)
				checkError(err)
				if !bytes.Equal(webPage, data) {
					log.Fatalln("incorrect web page data")
				}
				fmt.Println("http client keep alive")
				client.CloseIdleConnections()
			}()
			time.Sleep(1 + time.Duration(rand.Intn(250))*time.Millisecond)
		}
	}()
}

func kernel32Sleep() {
	go func() {
		var counter int
		for {
			// wait go routine run other test
			time.Sleep(1 + time.Duration(rand.Intn(10))*time.Millisecond)

			// trigger Gleam-RT SleepHR
			fmt.Println("call kernel32.Sleep [hooked]")
			now := time.Now()
			errno, _, _ := procSleep.Call(1 + uintptr(rand.Intn(10)))
			if errno != 0 {
				log.Fatalf("occurred error when sleep: %X\n", errno)
			}
			counter++
			fmt.Println("Sleep:", time.Since(now), "Times:", counter)
			fmt.Println()
		}
	}()
}

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
