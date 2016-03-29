kernel_version=2.6.18
dir=linux-$(kernel_version)
all: extract kpatch setting kernel initrd
extract:
	if [ ! -f .extract-done ]; then \
		echo "extract kernel source ... " && \
		tar zxf $(dir).tar.gz && \
		touch .extract-done ; \
	fi

kpatch:
	if [ ! -f .patch-done ]; then \
		cd $(dir) &&  \
		echo `pwd` && \
		echo "patch for iptables layer7 match module" && \
		patch -p1 < ../patch/kernel-2.6.18-layer7-2.6.patch && \
		echo "patch for iptables mirror target module" && \
		patch -p1 < ../patch/k2618-mirror_target_module.patch && \
		cd .. && \
		echo "kernel patch done." && \
		touch .patch-done ; \
	fi

setting:
	cp config-2.6.18 $(dir)/.config

kernel:	extract kpatch setting
	if [ -d $(dir) ]; then \
		$(MAKE) -C $(dir) && \
		touch .make-done ; \
	fi	

initrd:
	mkinitrd -o initrd.img $(kernel_version)

install: initrd
	$(MAKE) -C $(dir) modules_install
	$(MAKE) -C $(dir) install 

clean:
	if [ -d $(dir) ]; then \
		rm -rf $(dir) ; \
	fi
	if [ -f .extract-done ]; then \
		rm -rf .extract-done ; \
	fi
	if [ -f .patch-done ]; then \
		rm -rf .patch-done ; \
	fi
	if [ -f .make-done ]; then \
		rm -rf .make-done ; \
	fi
	if [ -f initrd.img ]; then \
		rm -f initrd.img ; \
	fi
