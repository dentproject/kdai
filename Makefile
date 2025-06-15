MODULE=kdai
PWD := $(shell pwd)
SRC := ${PWD}/src
BUILD := ${PWD}/build
KERNELRELEASE := $(shell uname -r)
KDIR := /lib/modules/${KERNELRELEASE}/build
MDIR := /lib/modules/${KERNELRELEASE}

.PHONY: all install remove clean

all:
	@echo "Building the module..."
	${MAKE} -C ${SRC} MODULE=${MODULE} KERNELRELEASE=${KERNELRELEASE} all
	mkdir -p ${BUILD}
	mv ${SRC}/${MODULE}.ko ${BUILD}/.
	@echo "Cleaning up temporary files..."
	rm -r -f ${SRC}/*.mod.c ${SRC}/.*.cmd ${SRC}/*.symvers ${SRC}/*.o
	@echo "Module built successfully."
install:
	@echo "Installing the module..."
	if [ ! -f  ${BUILD}/${MODULE}.ko ]; then \
		echo "Error: ${BUILD}/${MODULE}.ko not found. Did you try 'make all'?"; \
		exit 1; \
	fi
	sudo cp ${BUILD}/${MODULE}.ko ${MDIR}/.
	sudo depmod
	sudo modprobe ${MODULE}
	@echo "Module installed successfully."
remove:
	@echo "Removing the module..."
	sudo modprobe -r ${MODULE} || true
	sudo rm ${MDIR}/${MODULE}.ko || true
	@echo "Module removed successfully."
clean:
	@echo "Cleaning up build artifacts..."
	${MAKE} -C ${SRC} MODULE=${MODULE} KERNELRELEASE=${KERNELRELEASE} clean
	rm -rf ${BUILD}
	@echo "Build artifacts cleaned."