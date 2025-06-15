MODULE=kdai
PWD := $(shell pwd)
KERNELRELEASE := $(shell uname -r)
KDIR := /lib/modules/${KERNELRELEASE}/build
MDIR := /lib/modules/${KERNELRELEASE}
obj-m := ${MODULE}.o
${MODULE}-objs := main.o dhcp.o trusted_interfaces.o rate_limit.o vlan.o

all:
	@echo "Building the module..."
	make -C ${KDIR} M=${PWD} modules
	@echo "Cleaning up temporary files..."
	rm -r -f *.mod.c .*.cmd *.symvers *.o
install:
	@echo "Installing the module..."
	sudo cp kdai.ko ${MDIR}/.
	sudo depmod
	sudo modprobe kdai
	@echo "Module installed successfully."
remove:
	@echo "Removing the module..."
	sudo modprobe -r kdai
	sudo rm ${MDIR}/kdai.ko
	@echo "Module removed successfully."
clean:
	@echo "Cleaning up build artifacts..."
	make -C  ${KDIR} M=${PWD} clean
