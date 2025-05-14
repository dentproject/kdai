MODULE=kdai
PWD := $(shell pwd)
KERNELRELEASE := $(shell uname -r)
KDIR := /lib/modules/${KERNELRELEASE}/build
MDIR := /lib/modules/${KERNELRELEASE}
obj-m := ${MODULE}.o
${MODULE}-objs := main.o dhcp.o trustedInterfaces.o rate_limit.o vlan.o

all:
	@echo "Building the module..."
	@echo "Building the module..."
	make -C ${KDIR} M=${PWD} modules
	@echo "Cleaning up temporary files..."
	@echo "Cleaning up temporary files..."
	rm -r -f *.mod.c .*.cmd *.symvers *.o
install:
	@echo "Installing the module..."
	@echo "Installing the module..."
	sudo cp kdai.ko ${MDIR}/.
	sudo depmod
	sudo modprobe kdai
	@echo "Module installed successfully."
load_with_params:
	@echo "Installing the module for loading with parameters..."
	sudo cp kdai.ko ${MDIR}/.
	sudo depmod
	@echo "Module is Ready to Load."
	@echo "Use 'sudo modprobe kdai [globally_enabled_DAI=<0|1> static_ACL_Enabled=<0|1>...]' to load the module."
remove:
	@echo "Removing the module..."
	@echo "Removing the module..."
	sudo modprobe -r kdai
	sudo rm ${MDIR}/kdai.ko
	@echo "Module removed successfully."
	@echo "Module removed successfully."
clean:
	@echo "Cleaning up build artifacts..."
	@echo "Cleaning up build artifacts..."
	make -C  ${KDIR} M=${PWD} clean
