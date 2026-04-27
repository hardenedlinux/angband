obj-m += vuln_drill.o

KPATH ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KPATH) M=$(PWD) modules

clean:
	make -C $(KPATH) M=$(PWD) clean

help:
	@echo "vuln_drill -- CTF kernel challenge for Angband"
	@echo ""
	@echo "Build:    make"
	@echo "Install:  sudo insmod vuln_drill.ko"
	@echo "Remove:   sudo rmmod vuln_drill"
	@echo ""
	@echo "Interface:"
	@echo "  /proc/vuln_drill_act  -- write actions (alloc/free/callback/write)"
	@echo "  /proc/vuln_drill      -- stage tracking status"
	@echo ""
	@echo "For the basic ret2usr exploit, boot QEMU with:"
	@echo "  -cpu qemu64,-smep,-smap"
	@echo "  -append \"... nokaslr pti=off\""
