
all:
	GOOS=linux GOARCH=386 go build -o hello-stripped -ldflags "-s" hello.go
	GOOS=linux GOARCH=386 go build -o hello-normal hello.go
