BINARY := argus

.PHONY: build run scan baseline cross clean fmt vet

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) .

run: build
	./$(BINARY) scan

scan: build
	./$(BINARY) scan --out ./reports

baseline: build
	./$(BINARY) baseline

cross:
	bash scripts/build.sh

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist reports
