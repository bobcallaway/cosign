#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq (,$(shell echo $$DEBUG))
else
SHELL = bash -x
endif

# allow overwriting the default `go` value with the custom path to the go executable
GOEXE ?= go

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell $(GOEXE) env GOBIN))
GOBIN=$(shell $(GOEXE) env GOPATH)/bin
else
GOBIN=$(shell $(GOEXE) env GOBIN)
endif

# Set version variables for LDFLAGS
PROJECT_ID ?= projectsigstore
RUNTIME_IMAGE ?= gcr.io/distroless/static
GIT_TAG ?= dirty-tag
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --no-show-signature --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64
COSIGNED_ARCHS?=all

LDFLAGS=-buildid= -X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
        -X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
        -X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
        -X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE)

SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go")

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint

KO_PREFIX ?= gcr.io/projectsigstore
export KO_DOCKER_REPO=$(KO_PREFIX)
GHCR_PREFIX ?= ghcr.io/sigstore/cosign
LATEST_TAG ?=

.PHONY: all lint test clean cosign conformance cross
all: cosign

log-%:
	@grep -h -E '^$*:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk \
			'BEGIN { \
				FS = ":.*?## " \
			}; \
			{ \
				printf "\033[36m==> %s\033[0m\n", $$2 \
			}'

cosign: $(SRCS)
	CGO_ENABLED=0 $(GOEXE) build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/cosign

cosign-pivkey-pkcs11key: $(SRCS)
	CGO_ENABLED=1 $(GOEXE) build -trimpath -tags=pivkey,pkcs11key -ldflags "$(LDFLAGS)" -o cosign ./cmd/cosign

install: $(SRCS)
	CGO_ENABLED=1 $(GOEXE) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/cosign

install-pivkey-pkcs11key: $(SRCS)
	CGO_ENABLED=1 $(GOEXE) install -trimpath -tags=pivkey,pkcs11key -ldflags "$(LDFLAGS)" ./cmd/cosign

.PHONY: cross
cross:
	$(foreach GOOS, $(PLATFORMS),\
		$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); \
	$(GOEXE) build -trimpath -ldflags "$(LDFLAGS)" -o cosign-$(GOOS)-$(GOARCH) ./cmd/cosign; \
	shasum -a 256 cosign-$(GOOS)-$(GOARCH) > cosign-$(GOOS)-$(GOARCH).sha256 ))) \

#####################
# lint / test section
#####################

golangci-lint:
	rm -f $(GOLANGCI_LINT_BIN) || :
	set -e ;\
	GOBIN=$(GOLANGCI_LINT_DIR) $(GOEXE) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.2.2  ;\

lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT_BIN) run -n

test:
	$(GOEXE) test $(shell $(GOEXE) list ./... | grep -v third_party/)

clean:
	rm -rf cosign
	rm -rf dist/

KOCACHE_PATH=/tmp/ko
ARTIFACT_HUB_LABELS=--image-label io.artifacthub.package.readme-url="https://raw.githubusercontent.com/sigstore/cosign/main/README.md" \
                    --image-label io.artifacthub.package.logo-url=https://raw.githubusercontent.com/sigstore/cosign/main/images/logo.svg \
                    --image-label io.artifacthub.package.license=Apache-2.0 --image-label io.artifacthub.package.vendor=sigstore \
                    --image-label io.artifacthub.package.version=0.1.0 \
                    --image-label io.artifacthub.package.name=cosign \
                    --image-label org.opencontainers.image.created=$(BUILD_DATE) \
                    --image-label org.opencontainers.image.description="Container signing verification and storage in an OCI registry" \
                    --image-label io.artifacthub.package.alternative-locations="oci://ghcr.io/sigstore/cosign/cosign"

define create_kocache_path
  mkdir -p $(KOCACHE_PATH)
endef

###################
# conformance tests
###################

conformance:
	$(GOEXE) build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/conformance

CONFORMANCE_RUNNER_PATH = sigstore-conformance
$(CONFORMANCE_RUNNER_PATH):
	git clone https://github.com/sigstore/sigstore-conformance $@

.PHONY: conformance-runner
conformance-runner:
	$(MAKE) $(CONFORMANCE_RUNNER_PATH) conformance-runner-pull conformance-runner-build

.PHONY: conformance-runner-pull
conformance-runner-pull:
	cd $(CONFORMANCE_RUNNER_PATH) && git pull

.PHONY: conformance-runner-build
conformance-runner-build:
	cd $(CONFORMANCE_RUNNER_PATH) && $(MAKE) dev

CONFORMANCE_BIN = $(shell pwd)/conformance
.PHONY: conformance-tests
conformance-tests:
	cd $(CONFORMANCE_RUNNER_PATH) && env/bin/pytest test --entrypoint=$(CONFORMANCE_BIN)

##########
# ko build
##########
.PHONY: ko
ko: ko-cosign ko-cosign-dev

.PHONY: ko-cosign
ko-cosign:
	$(create_kocache_path)
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) ko build --base-import-paths \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH)$(LATEST_TAG) \
		$(ARTIFACT_HUB_LABELS) --image-refs cosignImagerefs \
		github.com/sigstore/cosign/v2/cmd/cosign

.PHONY: ko-cosign-dev
ko-cosign-dev:
	$(create_kocache_path)
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) KO_DEFAULTBASEIMAGE=gcr.io/distroless/static-debian12:debug-nonroot ko build --base-import-paths \
		--platform=all --tags $(GIT_VERSION)-dev --tags $(GIT_HASH)-dev$(LATEST_TAG)-dev \
		$(ARTIFACT_HUB_LABELS) --image-refs cosignDevImagerefs \
		github.com/sigstore/cosign/v2/cmd/cosign

.PHONY: ko-local
ko-local:
	$(create_kocache_path)
	KO_DOCKER_REPO=ko.local LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) ko build --base-import-paths \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) \
		$(ARTIFACT_HUB_LABELS) \
		github.com/sigstore/cosign/v2/cmd/cosign

.PHONY: ko-local-dev
ko-local-dev:
	$(create_kocache_path)
	KO_DOCKER_REPO=ko.local/cosign-dev LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) KO_DEFAULTBASEIMAGE=gcr.io/distroless/static-debian12:debug-nonroot ko build --base-import-paths \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) \
		$(ARTIFACT_HUB_LABELS) \
		github.com/sigstore/cosign/v2/cmd/cosign

##################
# help
##################

help: # Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort

include release/release.mk
include test/ci.mk

##########################
# Documentation generation
##########################

.PHONY: docgen
docgen:
	$(GOEXE) run -tags pivkey,pkcs11key,cgo ./cmd/help/
