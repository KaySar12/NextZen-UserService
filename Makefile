GORELEASER=goreleaser
GORELEASERBUILD=$(GORELEASER) build
SERVICE = casaos-user-service
ARCHITECHTURE= amd64
OS=linux
VERSION=v1
BIN_PATH=build/sysroot/usr/bin
BUILD_PATH=build
CUR_DIR=$(PWD)
TAG=v1.4.0
ARCHIVE_PATH=buildzip
PACKAGE_NAME=$(OS)-$(ARCHITECHTURE)-nextzenos-user-service-$(TAG)

build-service:
	$(GORELEASERBUILD) --clean --snapshot -f .goreleaser.debug.yaml --id $(SERVICE)-$(ARCHITECHTURE)

package:
	 cp -f $(CUR_DIR)/dist/$(SERVICE)-$(ARCHITECHTURE)_$(OS)_$(ARCHITECHTURE)_$(VERSION)/$(BIN_PATH)/$(SERVICE) $(CUR_DIR)/$(BIN_PATH) \
	 && tar -czvf $(PACKAGE_NAME).tar.gz $(CUR_DIR)/$(BUILD_PATH)

archive_package:
	mv $(PACKAGE_NAME).tar.gz $(CUR_DIR)/$(ARCHIVE_PATH)
remove_package:
	rm $(PACKAGE_NAME).tar.gz
clear_archive:
	rm -rf $(CUR_DIR)/$(ARCHIVE_PATH)/*