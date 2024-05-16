set GOARCH=amd64
go build -v -trimpath -ldflags "-s -w" -o go_amd64.exe main.go
set GOARCH=386
go build -v -trimpath -ldflags "-s -w" -o go_386.exe main.go