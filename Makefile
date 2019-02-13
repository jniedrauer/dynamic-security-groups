# Build config
BUILDFLAGS := -v -ldflags "-s -w -extldflags '-static'"
BUILDENV := GOOS=linux GOARCH=amd64 CGO_ENABLED=0
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
.PHONY: build
build: $(BUILDDIR)/dns-firewall

# Runs linters
.PHONY: lint
lint:
	$(GOLINT) -set_exit_status $(PKGS)

# Runs unit tests
.PHONY: test
test:
	@mkdir -p $(REPORTDIR)/xUnit
	$(TESTENV) $(GO) test $(TESTFLAGS) $(PKGS) \
		| tee -i /dev/stderr \
		| $(GOJUNITREPORT) -set-exit-code >$(REPORTDIR)/xUnit/test-report.xml

# Runs mod tidy
.PHONY: tidy
tidy:
	$(GO) mod tidy

# Packages build for distribution
.PHONY: dist
dist: build

# Cleans build directory tree
.PHONY: clean
clean:
	$(GO) clean -cache $(PKGS)
	-find $(BUILDDIR) -type f -exec rm {} \;

$(BUILDDIR)/%: $(wildcard $(CMDDIR)/**/*) $(SOURCES)
	 $(BUILDENV) $(GO) build $(BUILDFLAGS) -o $@ $<
