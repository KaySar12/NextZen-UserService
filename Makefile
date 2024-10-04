GORELEASER=goreleaser
GORELEASERBUILD=$(GORELEASER) build
GIT=git
GIT_REMOTE?=origin
SERVICE = casaos-user-service
ARCHITECHTURE= amd64
OS=linux
VERSION=v1
BIN_PATH=build/sysroot/usr/bin
BUILD_PATH=build
CUR_DIR=$(PWD)
CUR_TAG ?= $(shell git describe --tags --match '*.*.*' | sort -V | tail -n1)
PREV_TAG ?= $(shell git describe --tags --match '*.*.*' | sort -V | head -n2 | tail -n1)
ARCHIVE_PATH=buildzip
PACKAGE_NAME=$(OS)-$(ARCHITECHTURE)-nextzenos-user-service-$(TAG)

GIT_COMMIT_MESSAGE ?="update"
build_service:
	$(GORELEASERBUILD) --clean --snapshot -f .goreleaser.debug.yaml --id $(SERVICE)-$(ARCHITECHTURE)

package:
	 cp -f $(CUR_DIR)/dist/$(SERVICE)-$(ARCHITECHTURE)_$(OS)_$(ARCHITECHTURE)_$(VERSION)/$(BIN_PATH)/$(SERVICE) $(CUR_DIR)/$(BIN_PATH) \
	 && tar -czvf $(PACKAGE_NAME).tar.gz $(CUR_DIR)/$(BUILD_PATH)

archive_package:
	@mkdir -p $(CUR_DIR)/$(ARCHIVE_PATH)/$(CUR_TAG)
	@mv $(PACKAGE_NAME).tar.gz $(CUR_DIR)/$(ARCHIVE_PATH)/$(CUR_TAG)/
remove_package:
	rm $(PACKAGE_NAME).tar.gz
clear_archive:
	@rm -rf $(CUR_DIR)/$(ARCHIVE_PATH)
#make create_tag CUR_TAG=x.x TAG_MESSAGE="this is tag message"
create_tag:push_git
	@${GIT} tag -a ${CUR_TAG} -m "${TAG_MESSAGE}" || { echo "Failed to create tag"; exit 1; }
	@${GIT} push ${GIT_REMOTE} ${CUR_TAG} ||  { echo "Failed to push tag"; exit 1; }
#make remove_tag CUR_TAG=x.x
remove_tag:
	@${GIT} tag -d ${CUR_TAG}
	@${GIT} push ${GIT_REMOTE} -d ${CUR_TAG}	
check_tag:
	@echo "Previous tag: $(PREV_TAG)";
	@echo "Current tag: $(CUR_TAG)";  
push_release_all:push_git
	${GORELEASER} release --clean  -f .goreleaser.yaml
push_release:push_git
	${GORELEASER} release --single-target
push_git:
	@${GIT} pull ${GIT_REMOTE}
	@${GIT} add .
	@${GIT} commit -m "${GIT_COMMIT_MESSAGE}"
	@${GIT} push ${GIT_REMOTE}