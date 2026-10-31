# VERSION defines the project version. Update this value when you upgrade the
# version of your project.
VERSION ?= 0.0.8
# Must equal the GitHub repository name. Stakater's shared CI derives the image
# it advertises on the pull request and pulls back during e2e from the
# repository name alone, so an image pushed under any other name is one nothing
# downstream can find.
OPERATOR_NAME ?= openbao-config-operator
DOCKER_REPO_BASE ?= ghcr.io/marianu
ifeq ($(strip $(DOCKER_REPO_BASE)),)
DOCKER_REPO_BASE := ghcr.io/marianu
endif

# IMAGE_TAG_BASE defines the container registry namespace and part of the image
# name for remote images; it is used to construct the controller image tag.
IMAGE_TAG_BASE ?= $(DOCKER_REPO_BASE)/$(OPERATOR_NAME)
# Image URL to use all building/pushing image targets
IMG ?= $(IMAGE_TAG_BASE):v$(VERSION)$(GIT_TAG)
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
# Track the apiserver minor that the target OpenShift release ships (4.20 -> 1.33),
# so unit tests exercise the same API surface production does. Overridable so a
# skew run can point at another minor without editing this file.
ENVTEST_K8S_VERSION ?= 1.33.0

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

TEST_CLUSTER_NAME ?= e2e-test-cluster
ACTION ?= cluster

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

OPENBAO_NS   ?= openbao
OPERATOR_NS  ?= openbao-config-operator-system
VAULT_ADDR   ?= http://openbao.$(OPENBAO_NS).svc.cluster.local:8200
POLICY_FILE  ?= test/policies/obx-e2e-manage.hcl
TOKEN_SECRET ?= mto-openbao-token
TOKEN_KEY    ?= token

# Local/test VAULT_ADDR via port-forward (host can reach cluster svc)
VAULT_ADDR_LOCAL ?= http://127.0.0.1:18200

.PHONY: test-e2e
test-e2e:
	@echo "Running e2e with VAULT_ADDR=$(VAULT_ADDR_LOCAL)"
	@# 1) Port-forward OpenBao service -> localhost:18200
	@kubectl -n $(OPENBAO_NS) port-forward svc/openbao 18200:8200 >/tmp/pf.log 2>&1 & echo $$! > .pf.pid
	@# 2) Wait until the port responds (fail if it never does)
	@ok=0; \
	for i in $$(seq 1 60); do \
		if curl -sS -o /dev/null $(VAULT_ADDR_LOCAL)/v1/sys/health; then \
			echo "OpenBao reachable on 127.0.0.1:18200"; ok=1; break; \
		fi; \
		sleep 1; \
	done; \
	if [ $$ok -ne 1 ]; then \
		echo "ERROR: OpenBao not reachable on 127.0.0.1:18200 after 60s"; \
		kill $$(cat .pf.pid) >/dev/null 2>&1 || true; rm -f .pf.pid; \
		exit 1; \
	fi
	@# 2) Read limited token from Secret and run tests with env set
	@TOKEN=$$(kubectl -n $(OPERATOR_NS) get secret $(TOKEN_SECRET) \
		-o go-template='{{index .data "$(TOKEN_KEY)" | base64decode}}'); \
	if [ -z "$$TOKEN" ]; then echo "ERROR: empty VAULT_TOKEN from secret $(TOKEN_SECRET)"; \
	kill $$(cat .pf.pid) >/dev/null 2>&1 || true; rm -f .pf.pid; exit 1; fi; \
	VAULT_ADDR=$(VAULT_ADDR_LOCAL) VAULT_TOKEN="$$TOKEN" OPERATOR_NS=$(OPERATOR_NS) \
	OPENBAO_NS=$(OPENBAO_NS) OPENBAO_SVC=openbao OPENBAO_SCHEME=http OPENBAO_PORT=8200 \
	OPENBAO_TOKEN_SECRET=mto-openbao-token OPENBAO_TOKEN_KEY=token \
		go test ./test/e2e/ -v -ginkgo.v; \
	RC=$$?; \
	kill $$(cat .pf.pid) >/dev/null 2>&1 || true; rm -f .pf.pid; \
	if [ $$RC -ne 0 ]; then $(MAKE) e2e-diagnostics; fi; \
	exit $$RC

.PHONY: openbao-install
openbao-install: helm
	$(HELM) repo add openbao https://openbao.github.io/openbao-helm ;\
	$(HELM) repo update ;\
	$(HELM) upgrade openbao openbao/openbao --namespace $(OPENBAO_NS) --create-namespace --install --set server.dev.enabled=true

.PHONY: openbao-provision-creds
openbao-provision-creds:
	OPENBAO_NS=$(OPENBAO_NS) \
	OPERATOR_NS=$(OPERATOR_NS) \
	VAULT_ADDR=$(VAULT_ADDR) \
	VAULT_TOKEN=root \
	POLICY_NAME=obx-e2e-manage \
	POLICY_FILE=$(POLICY_FILE) \
	./hack/e2e/openbao/provision_credentials.sh

# Bootstraps the operator's own kubernetes-auth identity (mount, config,
# operator-manage policy, role). The operator then logs in with its
# ServiceAccount instead of reading a token from a Secret. Idempotent.
# VAULT_TOKEN=root matches the dev-mode openbao-install; production runs the
# script directly with a temp bootstrap token (see bootstrap-policy.hcl).
.PHONY: openbao-bootstrap-auth
openbao-bootstrap-auth:
	OPENBAO_NS=$(OPENBAO_NS) \
	OPERATOR_NS=$(OPERATOR_NS) \
	VAULT_ADDR=$(VAULT_ADDR) \
	VAULT_TOKEN=root \
	./hack/e2e/openbao/bootstrap_operator_auth.sh

.PHONY: operator-deploy
operator-deploy:
	kubectl create ns $(OPERATOR_NS) --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n $(OPERATOR_NS) apply -f hack/e2e/obx/rbac.yaml
	OPERATOR_IMAGE=$(OPERATOR_IMAGE) ./hack/apply_env_yaml.sh hack/e2e/obx/deploy.yaml.tmpl
	kubectl -n $(OPERATOR_NS) rollout status deploy/mto-openbao-extension --timeout=180s

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name openbao-config-operator-builder
	$(CONTAINER_TOOL) buildx use openbao-config-operator-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm openbao-config-operator-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: load-image
load-image: ## Load local image into Kind cluster if it exists locally, otherwise it will be pulled
	$(MAKE) cluster ACTION=load-image

# Wait for the controller rollout, dumping cluster state to stdout if it stalls
# and retrying once after a clean restart.
#
# The dump goes to stdout rather than to files under e2e-logs/ on purpose: this
# runs in `deploy`, which is upstream of `test-e2e`, so a failure here aborts the
# job before any artifact-uploading step is reached. Printing means the evidence
# lands in the workflow log, where it survives regardless.
#
# The retry is not just defensive. A private image on a cold Kind node has no
# local layer to reuse, and one fixed window gives a slow pull no second chance;
# ImagePullBackOff also burns through a short window in two or three attempts.
define rollout-controller-with-retry
@bash -ceu '\
	ns="$(OPERATOR_NS)"; \
	dep="$(OPERATOR_NAME)-controller-manager"; \
	echo ">>> Waiting for rollout (90s fast path)..."; \
	if ! $(KUBECTL) -n "$$ns" rollout status deploy/"$$dep" --timeout=90s; then \
	  echo ">>> Rollout stalled - collecting debug info before restart"; \
	  echo "---- Deployment describe ----"; \
	  $(KUBECTL) -n "$$ns" describe deploy/"$$dep" || true; \
	  echo "---- Pods (wide) ----"; \
	  $(KUBECTL) -n "$$ns" get pods -l control-plane=controller-manager -o wide || true; \
	  echo "---- Pod describe (image pull and config errors surface here) ----"; \
	  $(KUBECTL) -n "$$ns" describe pods -l control-plane=controller-manager || true; \
	  echo "---- Events (recent 20) ----"; \
	  $(KUBECTL) -n "$$ns" get events --sort-by=.lastTimestamp | tail -n 20 || true; \
	  echo "---- Pod logs (last 50, empty if no container started) ----"; \
	  for p in $$( $(KUBECTL) -n "$$ns" get pods -l control-plane=controller-manager -o name 2>/dev/null ); do \
	    echo "-- $$p --"; \
	    $(KUBECTL) -n "$$ns" logs "$$p" --tail=50 2>/dev/null || true; \
	  done; \
	  echo ">>> End of debug info"; \
	  echo ">>> Performing clean restart (scale 0 -> 1)..."; \
	  $(KUBECTL) -n "$$ns" scale deploy/"$$dep" --replicas=0; \
	  for i in $$(seq 1 24); do \
	    cnt="$$( $(KUBECTL) -n "$$ns" get pods -l control-plane=controller-manager --no-headers 2>/dev/null | wc -l | tr -d " " )"; \
	    [ "$$cnt" = "0" ] && break; \
	    sleep 5; \
	  done; \
	  $(KUBECTL) -n "$$ns" scale deploy/"$$dep" --replicas=1; \
	  echo ">>> Retrying rollout (210s)..."; \
	  $(KUBECTL) -n "$$ns" rollout status deploy/"$$dep" --timeout=210s; \
	fi; \
	$(KUBECTL) -n "$$ns" wait --for=condition=Available deploy/"$$dep" --timeout=120s; \
	echo ">>> Deployment $$dep successfully rolled out and ready."; \
	'
endef

.PHONY: e2e-diagnostics
e2e-diagnostics: ## Dump cluster state into ./e2e-logs, which CI uploads as an artifact on failure.
	mkdir -p e2e-logs
	-$(KUBECTL) -n $(OPERATOR_NS) get pods -o wide > e2e-logs/operator-pods.txt 2>&1
	-$(KUBECTL) -n $(OPERATOR_NS) describe pods >> e2e-logs/operator-pods.txt 2>&1
	-$(KUBECTL) -n $(OPERATOR_NS) logs deploy/$(OPERATOR_NAME)-controller-manager --tail=6000 > e2e-logs/controller.log 2>&1
	-$(KUBECTL) -n $(OPERATOR_NS) logs deploy/$(OPERATOR_NAME)-controller-manager --previous --tail=3000 > e2e-logs/controller-previous.log 2>&1
	-$(KUBECTL) -n $(OPENBAO_NS) get pods -o wide > e2e-logs/openbao-pods.txt 2>&1
	-$(KUBECTL) get events -A --sort-by=.lastTimestamp > e2e-logs/events.txt 2>&1
	-$(KUBECTL) get openbaopolicies,openbaosecretengines,openbaonamespaces -A -o yaml > e2e-logs/openbao-crs.yaml 2>&1

.PHONY: deploy
deploy: kustomize setup-cluster openbao-install openbao-provision-creds openbao-bootstrap-auth install
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG) && \
	$(KUSTOMIZE) edit set configmap controller-manager-config --from-literal=VAULT_ADDR='$(VAULT_ADDR)' --namespace $(OPERATOR_NS)
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply -f -
	$(KUBECTL) wait --for=condition=Established crd/openbaopolicies.security.mto.stakater.com --timeout=60s
	$(call rollout-controller-with-retry)

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: cluster
cluster: ## Setup Kind cluster with specified action (default: cluster). Usage: make cluster ACTION=<action>
	curl -sSL https://raw.githubusercontent.com/stakater/.github/refs/heads/main/.github/scripts/setup-kind-cluster.sh | \
	TEST_CLUSTER_NAME=$(TEST_CLUSTER_NAME) \
	IMG=$(IMG) \
	CONTAINER_TOOL=$(CONTAINER_TOOL) \
	KIND_VERSION=$(KIND_VERSION) \
	LOCALBIN=$(LOCALBIN) \
	OPERATOR_NAMESPACE=$(OPERATOR_NS) \
	PULL_SECRET_NAME=saap-dockerconfigjson \
	GHCR_USERNAME=$(GHCR_USERNAME) \
	GHCR_TOKEN=$(GHCR_TOKEN) \
	bash -s $(ACTION)

.PHONY: pull-secret
pull-secret: ## Create pull secret for private registry
	$(MAKE) cluster ACTION=pull-secret

.PHONY: setup-cluster
setup-cluster: ## Setup complete Kind cluster with image loading and pull secret
	$(MAKE) cluster ACTION=all

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
HELM ?= $(shell command -v helm || echo $(PWD)/bin/helm)
HELMIFY ?= $(LOCALBIN)/helmify
KIND ?= $(LOCALBIN)/kind

## Tool Versions
KUSTOMIZE_VERSION ?= v5.4.3
CONTROLLER_TOOLS_VERSION ?= v0.19.0
ENVTEST_VERSION ?= release-0.19
GOLANGCI_LINT_VERSION ?= v1.64.4
HELMIFY_VERSION ?= v0.4.20
KIND_VERSION ?= v0.30.0

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: helmify
helmify: $(HELMIFY)
$(HELMIFY): $(LOCALBIN)
	$(call go-install-tool,$(HELMIFY),github.com/arttor/helmify/cmd/helmify,${HELMIFY_VERSION})

.PHONY: helm
helm: $(HELM)
$(HELM): $(LOCALBIN)
	@if [ ! -f $(HELM) ]; then \
		echo "Downloading helm v3.19.0" ;\
		curl -sSLO https://get.helm.sh/helm-v3.19.0-linux-amd64.tar.gz ;\
		tar -zxvf helm-v3.19.0-linux-amd64.tar.gz ;\
		mv linux-amd64/helm $(HELM) ;\
		rm -rf linux-amd64 helm-v3.19.0-linux-amd64.tar.gz ;\
		chmod +x $(HELM) ;\
	else \
		echo "Helm already installed at $(HELM)" ;\
	fi

.PHONY: kind
kind: $(KIND)
$(KIND): $(LOCALBIN)
	$(call go-install-tool,$(KIND),sigs.k8s.io/kind,$(KIND_VERSION))

##@ Helm chart (operator)

HELM_CHART_NAME ?= $(OPERATOR_NAME)
HELM_CHART_DIR  ?= charts/$(HELM_CHART_NAME)

.PHONY: chart
chart: helmify kustomize yq ## Regenerate the operator chart from config/default (never commit).
	@rm -rf $(HELM_CHART_DIR)
	@mkdir -p $(HELM_CHART_DIR)
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/default | $(YQ_BIN) 'del(.. | .imagePullSecrets?)' | $(HELMIFY) -crd-dir -image-pull-secrets $(HELM_CHART_DIR)
	@$(YQ_BIN) -i '.name="$(HELM_CHART_NAME)" | .appVersion="$(VERSION)"' $(HELM_CHART_DIR)/Chart.yaml
	@n=$$(ls $(HELM_CHART_DIR)/crds | wc -l); echo "✓ chart generated at $(HELM_CHART_DIR) ($$n CRDs) — do NOT commit it"

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef

.PHONY: yq
YQ_VERSION := v4.44.3
YQ_BIN := $(LOCALBIN)/yq
yq:
ifeq (,$(wildcard $(YQ_BIN)))
	@{ \
	set -e ;\
	mkdir -p $(dir $(YQ_BIN)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(YQ_BIN) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$${OS}_$${ARCH} ;\
	chmod +x $(YQ_BIN) ;\
	}
endif

##@ Build

.PHONY: clean
clean: ## Remove generated build artifacts (local tooling, packaged charts, generated chart).
	@rm -rf $(LOCALBIN) dist build $(HELM_CHART_DIR)
	@echo "✓ Cleared generated artifacts (bin/, dist/, build/, $(HELM_CHART_DIR))"

