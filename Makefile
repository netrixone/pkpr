# Include variables
include .env.dist
-include .env
export

# Variables
INSTALL_DIR=$(shell dirname "`which $(BINARY_NAME)`")
GOFLAGS := -v
LDFLAGS := -s -w

############################################################
# HELP #####################################################
############################################################
all:
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"}'
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

############################################################
# DEVELOPMENT ##############################################
############################################################
clean:
	$(GOCMD) clean -i $(PACKAGE)
	rm -f $(BINARY_NAME)

build: deps
	$(GOCMD) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -a -v -o $(BINARY_NAME) $(PACKAGE)

deps:
	$(GOCMD) get -v -t ./...

test: build
	$(GOCMD) fmt $($(GOCMD) list ./... | grep -v /vendor/)
	$(GOCMD) vet $($(GOCMD) list ./... | grep -v /vendor/)
	$(GOCMD) test -race $($(GOCMD) list ./... | grep -v /vendor/)
