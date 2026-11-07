.PHONY: all build run test vet fmt tidy clean

BINARY_NAME=logguard

all: build

build:
	go build -o $(BINARY_NAME) ./cmd/logguard

run:
	go run ./cmd/logguard

test:
	go test -v ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	rm -f output/*.json output/*.enc output/*.bin output/*.sha256

