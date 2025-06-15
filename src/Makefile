obj-m := ${MODULE}.o
${MODULE}-objs := main.o dhcp.o trusted_interfaces.o rate_limit.o vlan.o module_params.o

ccflags-y := -I$(PWD)/include -Wall -Werror

all:
	make -C /lib/modules/${KERNELRELEASE}/build M=$(CURDIR) modules

clean:
	make -C /lib/modules/${KERNELRELEASE}/build M=$(CURDIR) clean