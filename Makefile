obj-m	:= pib_pcie_hpif.o pib_pcie_lwif.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

CPPFLAGS += -include $(KERNELDIR)/include/generated/autoconf.h
EXTRA_FLAGS += -Wno-error=date-time
EXTRA_CFLAGS +=-Wno-date-time
all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers *.order

