iptables_dir=iptables-1.3.6
compress_format=tar.gz
kerneldir=linux-2.6.18
l7protocol_tarball=l7-protocols-2006-10-18.tar.gz
l7protocol=l7-protocols-2006-10-18
all: extract ipatch iptables


extract: extract_l7_protocol
	if [ ! -f .extract-done ]; then \
		echo "extract iptables source $(iptables).$(compress_format)" && \
		tar zxf $(iptables_dir).$(compress_format) && \
		touch .extract-done ; \
	fi	

extract_l7_protocol:
	if [ -f $(l7protocol_tarball) ]; then \
		tar zxf $(l7protocol_tarball) && \
		touch .extract_l7-done ; \
	fi	

ipatch:
	if [ ! -f .patch-done ]; then \
		cd $(iptables_dir) && \
		echo "patch for iptables layer7 match module" && \
		patch -p1 < ../patch/iptables-layer7-2.6.patch && \
		echo "patch for iptables mirror target module" && \
		patch -p1 < ../patch/iptables-mirror_target_module.patch && \
		chmod +x extensions/.layer7-test && \
		touch .patch-done && \
		cd .. ; \
	fi

iptables: 
	if [ ! -f ../kernel/.make-done ]; then \
		echo "You must make your kernel source tree first" && \
		exit 1 ; \
	fi
	if [ ! -d ../kernel/$(kerneldir) ]; then \
		echo "Please extract kernel source first." && \
		exit 1; \
	fi
	if [ -d $(iptables_dir) ]; then \
		cd $(iptables_dir) && \
		make KERNEL_DIR=../../kernel/$(kerneldir) ; \
	fi

install_l7_protocol:
	if [ -f .extract_l7-done ]; then \
		cd $(l7protocol) && \
		make install ; \
	fi 

install: install_l7_protocol
	(cd $(iptables_dir) && make KERNEL_DIR=../../kernel/$(kerneldir) install)

clean_l7_protocol:
	if [ -f .extract_l7_protocol-done ]; then \
		rm -f .extract_l7_protocol-done; \
	fi
	if [ -d $(l7protocol) ]; then \
		rm -rf $(l7protocol); \
	fi

clean: clean_l7_protocol
	if [ -f .extract-done ]; then \
		rm -f .extract-done; \
	fi
	
	if [ -f .patch-done ]; then \
		rm -f .patch-done; \
	fi
	
	if [ -d $(iptables_dir) ]; then \
		rm -rf $(iptables_dir); \
	fi
