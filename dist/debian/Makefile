include ./CONFIG

UNAME=$(shell uname)
SUDO?=sudo
DEPENDS=
CROSSARCH=x64
PWD=$(shell pwd)
PACKAGE_DIR?=${PWD}

R2_VERSION=$(shell r2 -qv)

DOCKCROSS=$(PWD)/../dockcross

#R2PLUGDIR=$(shell r2 -H R2_LIBR_PLUGINS)
#R2PLUGDIR=/usr/lib/radare2/$(R2_VERSION)

ifeq ($(R2_LIBEXT),)
error:
	@echo "Cannot find r2"
endif

all: root
	$(SUDO) rm -rf control data
	$(MAKE) clean
	mkdir -p data
	cp -rf root/* data
	$(MAKE) control
	$(MAKE) deb

root:
	cd ../../ && cargo build --release
	mkdir -p root/usr/bin
	cp -f ../../target/release/radius2 root/usr/bin/radius2

purge: clean
	rm -rf root

summary:
	echo $(VERSION)

include deb.mk
