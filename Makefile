# Build config
BUILDFLAGS := -v -ldflags "-s -w -extldflags '-static'"
BUILDENV := GOOS=linux GOARCH=amd64
BUILDDIR := build
CMDDIR := cmd
TESTFLAGS := -v -race
TESTENV :=
REPORTDIR := $(BUILDDIR)/test-reports
PKGS := $(shell go list ./... | grep -v /vendor/)
SOURCES := $(shell find . -name '*.go')

# Executables
GO := GO111MODULE=on go
GOLINT := $(GO) run github.com/golang/lint/golint
GOJUNITREPORT := $(GO) run github.com/jstemmer/go-junit-report

# Default target
.PHONY: all
all: clean lint tidy dist

# Runs linters
.PHONY: lint
lint:
	$(GOLINT) -set_exit_status $(PKGS)

.PHONY: test
test:
	@mkdir -p $(REPORTDIR)
	$(TESTENV) $(GO) test $(TESTFLAGS) $(PKGS) \
		| tee -i /dev/stderr \
		| $(GOJUNITREPORT) -set-exit-code >$(REPORTDIR)/unit-test-report.xml

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: dist
dist: build

.PHONY: build
build: $(BUILDDIR)/dns-firewall

.PHONY: clean
clean:
	$(GO) clean -cache $(PKGS)
	-find $(BUILDDIR) -type f -exec rm {} \;

$(BUILDDIR)/%: $(wildcard $(CMDDIR)/**/*) $(SOURCES)
	 $(BUILDENV) $(GO) build $(BUILDFLAGS) -o $@ $<
