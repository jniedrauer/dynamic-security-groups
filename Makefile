BASENAME := dynamic-security-groups

# Build config
BUILDFLAGS := -v -ldflags "-s -w -extldflags '-static'"
BUILDENV := GOOS=linux GOARCH=amd64 CGO_ENABLED=0
BUILDDIR := build
DISTDIR := $(BUILDDIR)/dist
CMDDIR := cmd
TESTFLAGS := -v -race
TESTENV :=
REPORTDIR := $(BUILDDIR)/test-reports
PKGS := $(shell go list ./... | grep -v /vendor/)
SOURCES := $(shell find . -name '*.go')
HASH = $(shell git log -1 --pretty=%h)
TAG = $(shell git tag --points-at HEAD | sort --version-sort | tail -n 1)
TAR_ARCHIVE = $(BASENAME)-$(or $(TAG:v%=%), $(HASH)).tar.gz

# Executables
GO := GO111MODULE=on go
GOJUNITREPORT := $(GO) run github.com/jstemmer/go-junit-report
GOLINT := $(GO) run github.com/golang/lint/golint
TAR := tar

# Default target
.PHONY: build
build: $(BUILDDIR)/dns-firewall $(BUILDDIR)/aws-api-egress

# Runs linters
.PHONY: lint
lint:
	$(GOLINT) -set_exit_status $(PKGS)

# Runs unit tests
.PHONY: test
test:
	mkdir -p $(REPORTDIR)/xUnit
	$(TESTENV) $(GO) test $(TESTFLAGS) $(PKGS) \
		| tee -i /dev/stderr \
		| $(GOJUNITREPORT) -set-exit-code >$(REPORTDIR)/xUnit/test-report.xml

# Runs mod tidy
.PHONY: tidy
tidy:
	$(GO) mod tidy

# Packages build for distribution
.PHONY: dist
dist: $(DISTDIR)/$(TAR_ARCHIVE)

# Cleans build directory tree
.PHONY: clean
clean:
	$(GO) clean -cache $(PKGS)
	-find $(BUILDDIR) -type f -exec rm {} \;

$(DISTDIR)/$(TAR_ARCHIVE): $(BUILDDIR)/dns-firewall $(BUILDDIR)/aws-api-egress
	-mkdir -p $(DISTDIR)
	-rm -rf $(BUILDDIR)/tmp
	$(foreach bin, $^, \
		mkdir -p $(BUILDDIR)/tmp/$(BASENAME)/$(notdir $(bin)); \
		cp $(bin) $(BUILDDIR)/tmp/$(BASENAME)/$(notdir $(bin)); \
	)
	$(TAR) -C $(BUILDDIR)/tmp -czvf $(DISTDIR)/$(TAR_ARCHIVE) $(BASENAME)

$(BUILDDIR)/%: $(CMDDIR)/%/*.go $(SOURCES)
	 $(BUILDENV) $(GO) build $(BUILDFLAGS) -o $@ $<
