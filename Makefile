#obj-m += ksocket.o
obj-m += hello1.o
obj-m += rta_km.o
obj-m += hook_fn.o
obj-m += chardev.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
