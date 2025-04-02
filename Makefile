ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

GO_FILES = $(shell find . -type f -name '*.go')

all: lzr
	sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s $(source-ip) -j DROP

lzr: $(GO_FILES)
	cd cmd/lzr && go build && cd ../..
	rm -f lzr
	ln -s cmd/lzr/lzr$(EXECUTABLE_EXTENSION) lzr

lzr_race: $(GO_FILES)
	cd cmd/lzr && go build -race && cd ../..
	rm -f lzr
	ln -s cmd/lzr/lzr$(EXECUTABLE_EXTENSION) lzr

clean:
	cd cmd/lzr && go clean
	rm -f lzr
	@echo "Don't forget to delete iptables rule using:"
	@echo "sudo iptables -L --line-numbers && sudo iptables -D OUTPUT \TK"

clean_json:
	sudo rm *json

check:
	@echo "Running test cases..."
	@echo "======== TEST 1 ========"
	@printf "1.1.1.1:80\n1.1.1.2:443\n171.67.68.37:80\n171.67.68.37:1234\n104.81.3.98:80\n104.81.3.98:900\n" > services_list
	@<services_list pv -L 1 -l --quiet | sudo ./lzr --handshakes http -sendSYNs \
	-sourceIP 10.0.2.15 -gatewayMac 08:00:27:0b:29:a5 -sendInterface enp0s3 2>&1  \
	| (grep -qE "TotalResponses.:4" && echo "PASSED") || (echo "FAILED" && false)