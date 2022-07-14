#ifndef _PIB_PCIE_HPIF_CMD_H
#define _PIB_PCIE_HPIF_CMD_H

#define ALTERA_PCIE_DRIVER_VERSION "2.02"

#define ALTERA_PCIE_DID 0xE003
#define ALTERA_PCIE_VID 0x1172

#define ALTERA_IOCTL_SET_BAR        18
#define ALTERA_IOCTL_READ_CONF      19
#define ALTERA_IOCTL_GET_DMA_ADDR   20


#define TERASIC_IOCTL_READ_IRQ   1
#define TERASIC_IOCTL_CLEAN_IRQ   2

#include <linux/ioctl.h>

#define ALTERA_IOC_MAGIC   0x66
#define ALTERA_IOCX_SET_BAR          _IOW(ALTERA_IOC_MAGIC, ALTERA_IOCTL_SET_BAR, struct altera_ioctl_arg)
#define ALTERA_IOCX_READ_CONF        _IOR(ALTERA_IOC_MAGIC, ALTERA_IOCTL_READ_CONF, struct altera_ioctl_arg)
#define ALTERA_IOCX_GET_DMA_ADDR     _IOR(ALTERA_IOC_MAGIC, ALTERA_IOCTL_GET_DMA_ADDR, struct altera_ioctl_arg)


#define TERASIC_IOCX_READ_IRQ	    _IOR(ALTERA_IOC_MAGIC, TERASIC_IOCTL_READ_IRQ, struct altera_ioctl_arg)
#define TERASIC_IOCX_CLEAN_IRQ	    _IOW(ALTERA_IOC_MAGIC, TERASIC_IOCTL_CLEAN_IRQ, struct altera_ioctl_arg)


#ifdef __KERNEL__

#include <linux/pci.h>

#else

#include <sys/ioctl.h>
#include <inttypes.h>
typedef uint64_t dma_addr_t;
typedef uint64_t phys_addr_t;

#endif

#define ALTERA_DMA_DESCRIPTOR_NUM 128

#define ALTERA_LITE_DMA_RD_RC_LOW_SRC_ADDR      0x0000
#define ALTERA_LITE_DMA_RD_RC_HIGH_SRC_ADDR     0x0004
#define ALTERA_LITE_DMA_RD_CTLR_LOW_DEST_ADDR   0x0008
#define ALTERA_LITE_DMA_RD_CTRL_HIGH_DEST_ADDR  0x000C
#define ALTERA_LITE_DMA_RD_LAST_PTR             0x0010
#define ALTERA_LITE_DMA_RD_TABLE_SIZE           0x0014
#define ALTERA_LITE_DMA_RD_CONTROL              0x0018

#define ALTERA_LITE_DMA_WR_RC_LOW_SRC_ADDR      0x0100
#define ALTERA_LITE_DMA_WR_RC_HIGH_SRC_ADDR     0x0104
#define ALTERA_LITE_DMA_WR_CTLR_LOW_DEST_ADDR   0x0108
#define ALTERA_LITE_DMA_WR_CTRL_HIGH_DEST_ADDR  0x010C
#define ALTERA_LITE_DMA_WR_LAST_PTR             0x0110
#define ALTERA_LITE_DMA_WR_TABLE_SIZE           0x0114
#define ALTERA_LITE_DMA_WR_CONTROL              0x0118

#define DESC_CTRLLER_BASE               0x0000
#define ALTERA_DMA_CHUNK_SIZE           0x2000//8K bytes
#define DMA_TIMEOUT                     0x2000000

// PCIe control register addresses
#define ACL_PCI_CRA_BAR                         4
#define ACL_PCI_CRA_OFFSET                         0
#define ACL_PCI_CRA_SIZE                      0x4000
// PCI express control-register offsets
#define PCIE_CRA_IRQ_STATUS                   0xcf90
#define PCIE_CRA_IRQ_ENABLE                   0xcfa0
#define PCIE_CRA_ADDR_TRANS                   0x1000

// IRQ vector mappings (as seen by the PCIe RxIRQ port)
#define ACL_PCIE_KERNEL_IRQ_VEC                    0

#define PCIE_LED_STATUS                   0x4000010

#define TERASIC_VIP_SCHEDULE              0x80



// Handy macros
#define ACL_PCIE_READ_BIT( w, b ) (((w) >> (b)) & 1)
#define ACL_PCIE_READ_BIT_RANGE( w, h, l ) (((w) >> (l)) & ((1 << ((h) - (l) + 1)) - 1))
#define ACL_PCIE_SET_BIT( w, b ) ((w) |= (1 << (b)))
#define ACL_PCIE_CLEAR_BIT( w, b ) ((w) &= (~(1 << (b))))
#define ACL_PCIE_GET_BIT( b ) (unsigned) (1 << (b))

struct altera_ioctl_arg {

    /// The BAR to read from/write to in read and write functions
    int rw_bar_no;

    /// user buffer
    char *user_buffer_addr;
    /// the slave address to read/write
    dma_addr_t dma_rw_slave_addr;
    /// length of the DMA transaction in bytes
    unsigned long dma_length_byte;

    /// Read config data
    unsigned int offset;
    unsigned int data;

    /// Read irq
    unsigned int irq;
    unsigned int buffer_id;

    /// DMA address
    phys_addr_t rd_desc_table;
    phys_addr_t wr_desc_table;
    phys_addr_t rd_buffer;
    phys_addr_t wr_buffer;
    dma_addr_t rd_buffer_bus;
    dma_addr_t wr_buffer_bus;
};

struct dma_descriptor {
    uint32_t src_addr_ldw;
    uint32_t src_addr_udw;
    uint32_t dest_addr_ldw;
    uint32_t dest_addr_udw;
    uint32_t ctl_dma_len;
    uint32_t reserved[3];
} __attribute__ ((packed));

struct lite_dma_header {
    volatile uint32_t flags[128];
} __attribute__ ((packed));

struct lite_dma_desc_table {
    struct lite_dma_header header;
    struct dma_descriptor descriptors[ALTERA_DMA_DESCRIPTOR_NUM];
} __attribute__ ((packed));


#endif /* _ALTERA_PCIE_CMD_H */
