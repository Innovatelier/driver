#ifndef _PIB_PCIE__HPIF_H
#define _PIB_PCIE__HPIF_H

#include <linux/cdev.h>
#include <linux/pci.h>
#include "pib_pcie_hpif_cmd.h"

#define ALTERA_PCIE_DRIVER_NAME    "PIB PCIe HPIF"
#define ALTERA_PCIE_DEVFILE        "pib_pcie_hpif"

#define USE_MSI 1
#define POLLING 0

#define ALTERA_PCIE_BAR_NUM (6)

#define RD_CTRL_BUF_BASE_LOW			0x80000000
#define RD_CTRL_BUF_BASE_HI				0x0000
#define WR_CTRL_BUF_BASE_LOW			0x80002000
#define WR_CTRL_BUF_BASE_HI				0x0000

#define MAX_NUM_DWORDS                  0x100000//1M DWORDS
struct altera_pcie_dma_bookkeep {
    struct pci_dev *pci_dev;
    struct class *dev_class;
    struct device *device;
    
  /* Kernel irq - mustn't assume it's safe to enable kernel irq */
  char saved_kernel_irq_mask;

  /* signal sending structs */
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
  struct kernel_siginfo signal_info;
  struct kernel_siginfo signal_info_dma;
  #else
  struct siginfo signal_info;
  struct siginfo signal_info_dma;
  #endif
  //struct task_struct *user_task;
  //int signal_info;
  int user_filehandle;
  int signal_number;
  
  /* Debug data */  
  /* number of hw interrupts handled. */
  size_t num_handled_interrupts;
  size_t num_undelivered_signals;
  int pci_gen;
  int pci_num_lanes;
  
  /* PCI dma table and msi controls */
  u8 revision;
  u8 irq_pin;
  u8 irq_line;

    //u8 revision;
    //u8 irq_pin;
    char msi_enabled;
    //u8 irq_line;
    char dma_capable;

    void * __iomem bar[ALTERA_PCIE_BAR_NUM];
    size_t bar_length[ALTERA_PCIE_BAR_NUM];
    u32 rw_bar_no;

    struct lite_dma_desc_table *lite_table_rd_cpu_virt_addr;
    struct lite_dma_desc_table *lite_table_wr_cpu_virt_addr;

    dma_addr_t lite_table_rd_bus_addr;
    dma_addr_t lite_table_wr_bus_addr;

    phys_addr_t lite_table_rd_phys_addr;
    phys_addr_t lite_table_wr_phys_addr;

    int numpages;
    u8 *rp_rd_buffer_virt_addr;
    dma_addr_t rp_rd_buffer_bus_addr;
    phys_addr_t rp_rd_buffer_phys_addr;
    u8 *rp_wr_buffer_virt_addr;
    dma_addr_t rp_wr_buffer_bus_addr;
    phys_addr_t rp_wr_buffer_phys_addr;

    dev_t cdevno;
    struct cdev cdev;

    int user_pid;
    struct task_struct *user_task;
    wait_queue_head_t wait_q;
    atomic_t status;

};

static int scan_bars(struct altera_pcie_dma_bookkeep *bk_ptr, struct pci_dev *dev) __init;
static int map_bars(struct altera_pcie_dma_bookkeep *bk_ptr, struct pci_dev *dev) __init;
//static irqreturn_t dma_isr(int irq, void *dev_id);

static int altera_pci_probe(struct pci_dev *dev, const struct pci_device_id *id) __init;
static int scan_bars(struct altera_pcie_dma_bookkeep *bk_ptr, struct pci_dev *dev);
static void altera_pci_remove(struct pci_dev *dev) __exit;
//static int eplast_busy_wait(struct altera_pcie_dma_bookkeep *bk_ptr, u32 expected_eplast, u8 rw);
#ifdef MEASURE_TIME
static int diff_timeval(struct timeval *result, struct timeval *t2, struct timeval *t1);
#endif
static int init_chrdev (struct altera_pcie_dma_bookkeep *bk_ptr) __init;

ssize_t altera_pcie_read(struct file *file, char __user *buf, size_t count, loff_t *pos);
ssize_t altera_pcie_write(struct file *file, const char __user *buf, size_t count, loff_t *pos);
int altera_pcie_open(struct inode *inode, struct file *file);
int altera_pcie_release(struct inode *inode, struct file *file);
static long altera_pcie_ioctl (struct file *filp, unsigned int cmd, unsigned long arg);

/* aclpci.c functions */
void load_signal_info (struct altera_pcie_dma_bookkeep *bk_ptr);
int init_irq (struct pci_dev *dev, void *dev_id);
void release_irq (struct pci_dev *dev, void *bk_ptr);
void unmask_kernel_irq(struct altera_pcie_dma_bookkeep *bk_ptr);
void mask_kernel_irq(struct altera_pcie_dma_bookkeep *bk_ptr);

#endif /* _PIB_PCIE__HPIF_H */
