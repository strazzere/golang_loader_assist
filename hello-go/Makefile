GO=go

all:
	GOOS=linux GOARCH=386 $(GO) build -o hello-stripped -ldflags "-s" hello.go
	GOOS=linux GOARCH=386 $(GO) build -o hello-normal hello.go
