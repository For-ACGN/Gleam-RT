package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

func main() {
	var (
		addr    string
		dir     string
		cert    string
		key     string
		handler string
	)
	flag.StringVar(&addr, "addr", ":8001", "http server port")
	flag.StringVar(&dir, "dir", "res", "resource directory path")
	flag.StringVar(&cert, "cert", "", "tls certificate (pem)")
	flag.StringVar(&key, "key", "", "private key (pem)")
	flag.StringVar(&handler, "handler", "/", "web handler")
	flag.Parse()

	switch handler {
	case "/":
	default: // "a" -> "/a/"
		hRune := []rune(handler)
		if len(hRune) == 1 {
			handler = fmt.Sprintf("/%s/", handler)
		} else {
			r := '/'
			if hRune[0] != r {
				hRune = append([]rune("/"), hRune...)
			}
			if hRune[len(hRune)-1] != r {
				hRune = append(hRune, r)
			}
			handler = string(hRune)
		}
	}

	server := http.Server{
		Addr: addr,
	}
	fileServer := http.FileServer(http.Dir(dir))
	handlerFn := func(w http.ResponseWriter, r *http.Request) {
		dumpRequest(r)
		// prevent incorrect cache
		r.Header.Del("If-Modified-Since")
		// redirect for process file directory
		path := strings.ReplaceAll(r.URL.Path, handler, "/")
		path = strings.ReplaceAll(filepath.Clean(path), "\\", "/")
		// prevent directory traversal
		if path == "/" {
			return
		}
		r.URL.Path = path
		// process file
		fileServer.ServeHTTP(w, r)
	}
	serveMux := http.NewServeMux()
	serveMux.HandleFunc(handler, handlerFn)
	server.Handler = serveMux

	var err error
	if cert != "" && key != "" {
		err = server.ListenAndServeTLS(cert, key)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		log.Fatalln(err)
	}
}

func dumpRequest(r *http.Request) {
	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	_, _ = fmt.Fprintf(buf, "Remote: %s\n", r.RemoteAddr)
	_, _ = fmt.Fprintf(buf, "%s %s %s", r.Method, r.RequestURI, r.Proto)
	_, _ = fmt.Fprintf(buf, "\nHost: %s", r.Host)
	for k, v := range r.Header {
		_, _ = fmt.Fprintf(buf, "\n%s: %s", k, v[0])
	}
	log.Printf("handle request\n%s\n\n", buf)
}
