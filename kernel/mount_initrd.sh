#!/bin/sh

start(){
	if [ ! -d "initrd-test" ]; then mkdir initrd-test; fi
	mount -t cramfs -o loop initrd.img initrd-test
}

stop(){
	umount ./initrd-test
	rm -rf initrd-test
}

case $1 in
"start")
	start;;
"stop")
	stop;;
*)
	echo "Usage: $0 start/stop"
esac
