obj-m += vuln_drill.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	@echo "Load with: sudo insmod vuln_drill.ko"
	@echo "Interact via /proc/vuln_drill and ioctl 0xDEADBEEF"
	@echo "Use for grooming, trigger, and escalation testing (CFI/CET aware)"