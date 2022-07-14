#include <linux/fs.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <asm/siginfo.h>
#include <linux/version.h>
#include "pib_pcie_hpif.h"
#include "pib_pcie_hpif_cmd.h"


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif


#define DEVICE_MAJOR 0x0
static int device_major = DEVICE_MAJOR;
module_param(device_major, int, S_IRUGO);
static int device_minor_count = 0;
static int data_done=0; 
static int lidar_buffer_index=0,cam0_buffer_index=0,cam1_buffer_index=0,cam2_buffer_index=0,cam3_buffer_index=0;
unsigned long mask=0x00,buffer_index=0;

/// The default vendor ID that the driver support
static int vendor_id = ALTERA_PCIE_VID;
module_param(vendor_id, int, S_IRUGO);
/// The default device ID that the driver support
static int device_id = ALTERA_PCIE_DID;
module_param(device_id, int, S_IRUGO);

static long altera_pcie_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct altera_pcie_dma_bookkeep *bk_ptr = filp->private_data;
    struct altera_ioctl_arg kernel_arg;

    // verify arg in user process
    if (access_ok((void __user *)arg, _IOC_SIZE(cmd))) {
        // copy ioctl arg from user space to kernel
        if (copy_from_user(&kernel_arg, (int __user *)arg, sizeof(struct altera_ioctl_arg))){
            return -EFAULT;
        }
    } else {
        return -EFAULT;
    }

    switch (cmd) {
        case ALTERA_IOCX_SET_BAR:
            if (kernel_arg.rw_bar_no < 0 || kernel_arg.rw_bar_no >= ALTERA_PCIE_BAR_NUM) {
                dev_err(&bk_ptr->pci_dev->dev, "Error: invalid BAR number. \n");
                return -EFAULT;
            } else if (bk_ptr->bar[kernel_arg.rw_bar_no] == NULL) {
                dev_err(&bk_ptr->pci_dev->dev, "Error: try to access the unintialized BAR. \n");
                return -EFAULT;
            }
            bk_ptr->rw_bar_no = kernel_arg.rw_bar_no;
            break;
        case ALTERA_IOCX_READ_CONF:
            if (pci_read_config_dword(bk_ptr->pci_dev, kernel_arg.offset, &kernel_arg.data) < 0) {
                dev_err(&bk_ptr->pci_dev->dev, "Read pci config is fail. \n");
                return -EFAULT;
            } else {
                if (access_ok((void __user *)arg, _IOC_SIZE(cmd))) {
                    // copy ioctl arg from kernel space to user
                    if (copy_to_user((struct altera_ioctl_arg *)arg, &kernel_arg, sizeof(struct altera_ioctl_arg))) {
                        return -EFAULT;
                    }
                } else {
                    return -EFAULT;
                }
            }
            break;
	case TERASIC_IOCX_READ_IRQ:
		kernel_arg.irq = data_done;
		kernel_arg.buffer_id= buffer_index;
                if (access_ok((void __user *)arg, _IOC_SIZE(cmd))) {
                    // copy ioctl arg from kernel space to user
                    if (copy_to_user((struct altera_ioctl_arg *)arg, &kernel_arg, sizeof(struct altera_ioctl_arg))) {
                        return -EFAULT;
                    }
                } else {
                    return -EFAULT;
                }
            	break;

	case TERASIC_IOCX_CLEAN_IRQ:
		data_done = 0;
            	break;
	
        case ALTERA_IOCX_GET_DMA_ADDR:
            kernel_arg.rd_desc_table = bk_ptr->lite_table_rd_phys_addr;
            kernel_arg.wr_desc_table = bk_ptr->lite_table_wr_phys_addr;
            kernel_arg.rd_buffer = bk_ptr->rp_rd_buffer_phys_addr;
            kernel_arg.wr_buffer = bk_ptr->rp_wr_buffer_phys_addr;
            kernel_arg.rd_buffer_bus = bk_ptr->rp_rd_buffer_bus_addr;
            kernel_arg.wr_buffer_bus = bk_ptr->rp_wr_buffer_bus_addr;
            if (access_ok((void __user *)arg, _IOC_SIZE(cmd))) {
                // copy ioctl arg from kernel space to user
                if (copy_to_user((struct altera_ioctl_arg *)arg, &kernel_arg, sizeof(struct altera_ioctl_arg))) {
                    return -EFAULT;
                }
            } else {
                return -EFAULT;
            }
            break;
        default:
            return -EINVAL;
    }
    return 0;
}

ssize_t altera_pcie_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    char *kernel_buf;
    ssize_t bytes_read = 0;
    struct altera_pcie_dma_bookkeep *bk_ptr = filp->private_data;

    // error checking
    if (*f_pos + count > bk_ptr->bar_length[bk_ptr->rw_bar_no]) {
        dev_err(&bk_ptr->pci_dev->dev, "Trying to read from the outside of the BAR. \n");
        return -1;
    }

    // allocate kernel buffer for reading
    kernel_buf = kmalloc(count * sizeof(char), GFP_KERNEL);

    // check whether count and file position are multiple of 4
    if ((count % 4 == 0) && (*f_pos % 4 == 0)) {
        while (count > 0) {
            // read 32 bits each time
            ((u32 *)kernel_buf)[bytes_read/4] = ioread32(bk_ptr->bar[bk_ptr->rw_bar_no] + *f_pos);

            count -= sizeof(u32);
            bytes_read += sizeof (u32);
            *f_pos += sizeof(u32);
        }
    } else {
        while (count > 0) {
            // read 8 bits each time
            kernel_buf[bytes_read] = ioread8(bk_ptr->bar[bk_ptr->rw_bar_no] + *f_pos);

            count -= sizeof(u8);
            bytes_read += sizeof (u8);
            *f_pos += sizeof(u8);
        }
    }

    // check the user buffer writable
    if (access_ok((void __user *)buf, bytes_read)) {
        // check the return value, if return not 0, copy imcompletely
        if (copy_to_user(buf, kernel_buf, bytes_read)) {
            dev_err(&bk_ptr->pci_dev->dev, "copy_to_user() failed. \n");
            return -1;
        }
    } else {
        dev_err(&bk_ptr->pci_dev->dev, "access_ok() failed. \n");
        return -1;
    }

    // free the buffer after reading
    kfree(kernel_buf);

    // return the number for bytes read
    return bytes_read;
}

ssize_t altera_pcie_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    char *kernel_buf;
    ssize_t bytes_written = 0;
    struct altera_pcie_dma_bookkeep *bk_ptr = filp->private_data;

    // error checking
    if (*f_pos + count > bk_ptr->bar_length[bk_ptr->rw_bar_no]) {
        dev_err(&bk_ptr->pci_dev->dev, "Trying to write to the outside of the BAR. \n");
        return -1;
    }

    // allocate the kernel buffer
    kernel_buf = kmalloc(count * sizeof(char), GFP_KERNEL);

    // check whether the user buffer is readable
    if (access_ok((void __user *)buf, count)) {
        // check the return value, if return not 0, copy imcompletely
        if (copy_from_user(kernel_buf, buf, count)) {
            dev_err(&bk_ptr->pci_dev->dev, "copy_from_user() failed. \n");
            return -1;
        }
    } else {
        dev_err(&bk_ptr->pci_dev->dev, "access_ok() failed. \n");
        return -1;
    }

    // check whether count and file position are multiple of 4
    if ((count % 4 == 0) && (*f_pos % 4 == 0)) {
        while (count > 0) {
            // write 32 bits each time
            iowrite32(((u32 *)kernel_buf)[bytes_written/4], bk_ptr->bar[bk_ptr->rw_bar_no] + *f_pos);

            count -= sizeof(u32);
            bytes_written += sizeof(u32);
            *f_pos += sizeof(u32);
        }
    } else {
        while (count > 0) {
            // write 8 bits each time
            iowrite8(kernel_buf[bytes_written], bk_ptr->bar[bk_ptr->rw_bar_no] + *f_pos);

            count -= sizeof(u8);
            bytes_written += sizeof(u8);
            *f_pos += sizeof(u8);
        }
    }

    // free the kernel buffer after writing
    kfree(kernel_buf);

    // return the number of bytes written
    return bytes_written;
}

static int altera_pcie_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct altera_pcie_dma_bookkeep *bk_ptr = filp->private_data;
    unsigned long size = vma->vm_end - vma->vm_start;
    dev_info(&bk_ptr->pci_dev->dev, "mmap, start %lx end %lx off %lx \n", vma->vm_start, vma->vm_end, vma->vm_pgoff);
    remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, size, vma->vm_page_prot);
#ifdef VM_RESERVED
    vma->vm_flags |= VM_IO | VM_RESERVED;
#else
    vma->vm_flags |= VM_IO;
#endif

    return 0;
}

static loff_t  altera_pcie_llseek (struct file *filp, loff_t off, int whence)
{

    loff_t newpos;

    switch (whence) {
        case 0: /* SEEK_SET */ // set the off, starting from the beginning of the file
            newpos = off;
            break;
        case 1: /* SEEK_CUR */ // set the off, starting from the current file position
            newpos = filp->f_pos + off;
            break;
        case 2: /* SEEK_END */
            newpos = -1;  // should not be set outside the range of the BAR address
            break;
        default: /* can't happen */
            return -EINVAL;
    }
    if (newpos < 0)
        return -EINVAL;

    filp->f_pos = newpos;
    return newpos;
}
///////////////////// add  by pxx  /////////////////////

/* Returns virtual mem address corresponding to location of IRQ control
 * register of the board */
static void* get_interrupt_enable_addr(struct altera_pcie_dma_bookkeep *bk_ptr) {

  /* Bar 2, register PCIE_CRA_IRQ_ENABLE is the IRQ enable register PCIE_CRA_IRQ_ENABLE 
   * (among other things). */
  return (void*)(bk_ptr->bar[4] + (unsigned long)PCIE_CRA_IRQ_ENABLE);
}


static void* get_interrupt_status_addr(struct altera_pcie_dma_bookkeep *bk_ptr) {

  /* Bar 2, register PCIE_CRA_IRQ_ENABLE is the IRQ enable register
   * (among other things). */
  return (void*)(bk_ptr->bar[4] + (unsigned long)PCIE_CRA_IRQ_STATUS);
}


static void* get_led_status_addr(struct altera_pcie_dma_bookkeep *bk_ptr) {

  /* Bar 2, register PCIE_CRA_IRQ_ENABLE is the IRQ enable register
   * (among other things). */
  return (void*)(bk_ptr->bar[4] + (unsigned long)PCIE_LED_STATUS);
}


static void* get_vip_schedule_addr(struct altera_pcie_dma_bookkeep *bk_ptr,int offset) {

  return (void*)(bk_ptr->bar[4] + (unsigned long)(TERASIC_VIP_SCHEDULE + offset*0x04));
}



/* Enable interrupt generation on the device. */
static void unmask_irq(struct altera_pcie_dma_bookkeep *bk_ptr) {
	
  u32 val = 0;

  /* Restore kernel irq mask */
  if (bk_ptr->saved_kernel_irq_mask)
    val = ACL_PCIE_GET_BIT(ACL_PCIE_KERNEL_IRQ_VEC);
    writel (0x00, get_interrupt_enable_addr(bk_ptr));
}


/* Disable interrupt generation on the device. */
static void mask_irq(struct altera_pcie_dma_bookkeep *bk_ptr) {
	
  /* Save kernel irq mask */
  bk_ptr->saved_kernel_irq_mask = ACL_PCIE_READ_BIT(readl(get_interrupt_enable_addr(bk_ptr)),ACL_PCIE_KERNEL_IRQ_VEC);
  writel (0x0, get_interrupt_enable_addr(bk_ptr));
  //Read again to ensure the writel is finished
  //Without doing this might cause the programe moving
  //forward without properly mask the irq.
  readl(get_interrupt_enable_addr(bk_ptr));
}


/* Enable interrupt generation on the device. */
void unmask_kernel_irq(struct altera_pcie_dma_bookkeep *bk_ptr) {
	
  u32 val = 0;
  val = readl(get_interrupt_enable_addr(bk_ptr));
  val |= ACL_PCIE_GET_BIT(ACL_PCIE_KERNEL_IRQ_VEC);

  writel (val, get_interrupt_enable_addr(bk_ptr));
}

//
// IDENTICAL COPY OF THIS FUNCTION IS IN HAL/PCIE.
// KEEP THE TWO COPIES IN SYNC!!!
//
// Given irq status, determine type of interrupt
// Result is returned in kernel_update/dma_update arguments.
// Using 'int' instead of 'bool' for returns because the kernel code
// is pure C and doesn't support bools.
void get_interrupt_type (unsigned int irq_status,
                         unsigned int *kernel_update)
{
   *kernel_update = ACL_PCIE_READ_BIT(irq_status, ACL_PCIE_KERNEL_IRQ_VEC );
   
}

void mask_kernel_irq(struct altera_pcie_dma_bookkeep *bk_ptr){

  u32 val;
  val = readl(get_interrupt_enable_addr(bk_ptr));

  if((val & ACL_PCIE_GET_BIT(ACL_PCIE_KERNEL_IRQ_VEC)) != 0){
    val ^= ACL_PCIE_GET_BIT(ACL_PCIE_KERNEL_IRQ_VEC);
  }

  writel (val, get_interrupt_enable_addr(bk_ptr));
  //Read again to ensure the writel is finished
  //Without doing this might cause the programe moving
  //forward without properly mask the irq.
  val = readl(get_interrupt_enable_addr(bk_ptr));
}


int altera_pcie_open(struct inode *inode, struct file *filp)
{
    struct altera_pcie_dma_bookkeep *bk_ptr = 0;

    bk_ptr = container_of(inode->i_cdev, struct altera_pcie_dma_bookkeep, cdev);
    filp->private_data = bk_ptr;
    bk_ptr->user_pid = current->pid;
    unmask_irq(bk_ptr);
    return 0;
}

int altera_pcie_release(struct inode *inode, struct file *filp)
{
    return 0;
}

struct file_operations altera_pcie_fops = {
    .owner          = THIS_MODULE,
    .read           = altera_pcie_read,
    .write          = altera_pcie_write,
    .open           = altera_pcie_open,
    .release        = altera_pcie_release,
    .unlocked_ioctl = altera_pcie_ioctl,
    .llseek         = altera_pcie_llseek,
    .mmap           = altera_pcie_mmap,
};

static int __init init_chrdev(struct altera_pcie_dma_bookkeep *bk_ptr)
{
    int result;
    int dev_minor = device_minor_count;

    if (device_major == 0) {
        result = alloc_chrdev_region(&bk_ptr->cdevno, 0, 1, ALTERA_PCIE_DEVFILE);
        device_major = MAJOR(bk_ptr->cdevno);
    } else {
        bk_ptr->cdevno = MKDEV(device_major, dev_minor);
        result = register_chrdev_region(bk_ptr->cdevno, 1, ALTERA_PCIE_DEVFILE);
    }

    if (result < 0) {
        dev_err(&bk_ptr->pci_dev->dev, "cannot get major ID");
    }

    cdev_init(&bk_ptr->cdev, &altera_pcie_fops);
    bk_ptr->cdev.owner = THIS_MODULE;
    bk_ptr->cdev.ops = &altera_pcie_fops;
    result = cdev_add(&bk_ptr->cdev, bk_ptr->cdevno, 1);

    if (result)
        return -1;
    device_minor_count++;
    return 0;
}



#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
irqreturn_t aclpci_irq (int irq, void *dev_id, struct pt_regs * not_used) {
#else
irqreturn_t aclpci_irq (int irq, void *dev_id) {
#endif


  struct altera_pcie_dma_bookkeep *bk_ptr = (struct altera_pcie_dma_bookkeep *)dev_id;

  u32 irq_status;
  irqreturn_t res;
  u32 val = 0;
  unsigned int kernel_update = 0, dma_update = 0;
   
  if (bk_ptr == NULL) {
    return IRQ_NONE;
  }

  /* From this point on, this is our interrupt. So return IRQ_HANDLED
   * no matter what (since nobody else in the system will handle this
   * interrupt for us). */
  bk_ptr->num_handled_interrupts++;

  /* Can get interrupt for two reasons --  DMA descriptor processing is done
   * or kernel has finished. DMA is done entirely in the driver, so check for
   * that first and do NOT notify the user. */
  irq_status = readl(get_interrupt_status_addr(bk_ptr));

  if(irq_status!=0x00){
  	if ((irq_status&0x01)==0x01) {
		val=(readl(get_vip_schedule_addr(bk_ptr,5))>>24)&0xff;
    		if(val==0)
    			lidar_buffer_index=15;
    		else	
    			lidar_buffer_index=val-1;
		buffer_index = 0x10 | lidar_buffer_index ;
 		data_done = 1;
    		writel (0x01, get_vip_schedule_addr(bk_ptr,5));	
    		res = IRQ_HANDLED;
  	} 	 
  	if ((irq_status&0x02)==0x02) {
		val=(readl(get_vip_schedule_addr(bk_ptr,6))>>24)&0xff;
    		if(val==0)
    			cam0_buffer_index=15;
    		else	
    			cam0_buffer_index=val-1;
		buffer_index = 0x20 | cam0_buffer_index ;
 		data_done = 1;
    		writel (0x01, get_vip_schedule_addr(bk_ptr,6));	
    		res = IRQ_HANDLED;
  	}
  	if ((irq_status&0x04)==0x04) {
		val=(readl(get_vip_schedule_addr(bk_ptr,7))>>24)&0xff;
    		if(val==0)
    			cam1_buffer_index=15;
    		else	
    			cam1_buffer_index=val-1;
		buffer_index = 0x40 | cam1_buffer_index ;
		data_done = 1;
    		writel (0x01, get_vip_schedule_addr(bk_ptr,7));	
    		res = IRQ_HANDLED;
  	}
  	if ((irq_status&0x08)==0x08) {
		val=(readl(get_vip_schedule_addr(bk_ptr,8))>>24)&0xff;
    		if(val==0)
    			cam2_buffer_index=15;  			
    		else	
    			cam2_buffer_index=val-1;
		buffer_index = 0x80 | cam2_buffer_index ;
		data_done = 1;
    		writel (0x01, get_vip_schedule_addr(bk_ptr,8));	
    		res = IRQ_HANDLED;
  	}
  	if ((irq_status&0x10)==0x10) {
		val=(readl(get_vip_schedule_addr(bk_ptr,9))>>24)&0xff;
    		if(val==0)
    			cam3_buffer_index=15;   			
    		else	
    			cam3_buffer_index=val-1;
		buffer_index = 0x100 | cam3_buffer_index ;
		data_done = 1;
    		writel (0x01, get_vip_schedule_addr(bk_ptr,9));	
    		res = IRQ_HANDLED;
  	}
   	else{  
     		res = IRQ_HANDLED;   
  	}
  }

  return res;
}



int init_irq (struct pci_dev *dev, void *dev_id) {

  u32 irq_type;
  struct altera_pcie_dma_bookkeep *bk_ptr = (struct altera_pcie_dma_bookkeep*)dev_id;
  int rc,rr;
  bool flag;

  if (dev == NULL || bk_ptr == NULL) {
    dev_info(&dev->dev, "Invalid inputs to init_irq (%p, %p)", dev, dev_id);
    return -1;
  }

  /* Message Signalled Interrupts. */
  #if USE_MSI
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
  rr=0;
  rr= pci_alloc_irq_vectors(dev,1,4,PCI_IRQ_MSI);
  #else
  if(pci_enable_msi(dev) != 0){
    dev_info(&dev->dev, "Could not enable MSI");
  }
  #endif
  if (!pci_set_dma_mask(dev, DMA_BIT_MASK(64))) {
    pci_set_consistent_dma_mask(dev, DMA_BIT_MASK(64));
    dev_info(&dev->dev, "using a 64-bit irq mask\n");
  } else {
    dev_info(&dev->dev, "unable to use 64-bit irq mask\n");
    pci_disable_msi(dev);
    return -1;
  }
  #endif

  /* Do NOT use PCI_INTERRUPT_LINE config register. Its value is different
   * from dev->irq and doesn't work! Why? Who knows! */

  /* IRQF_SHARED   -- allow sharing IRQs with other devices */
  #if !USE_MSI
    irq_type = IRQF_SHARED;
  #else
    /* No need to share MSI interrupts since they don't use dedicated wires.*/
    irq_type = 0;
  #endif

  pci_read_config_byte(dev, PCI_REVISION_ID, &bk_ptr->revision);
  pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &bk_ptr->irq_pin);
  pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &bk_ptr->irq_line);

  dev_info(&dev->dev,"irq pin: %d\n", bk_ptr->irq_pin);
  dev_info(&dev->dev,"irq line: %d\n", bk_ptr->irq_line);
  dev_info(&dev->dev,"irq: %d\n", dev->irq);

  rc = request_irq (dev->irq, aclpci_irq, irq_type, ALTERA_PCIE_DRIVER_NAME, dev_id);
  //rc = request_irq (bk_ptr->irq_line, aclpci_irq, irq_type, ALTERA_PCIE_DRIVER_NAME, (void *)bk_ptr);
  if (rc) {
    dev_info(&dev->dev, "Could not request IRQ #%d, error %d", dev->irq, rc);
    return -1;
  }
  pci_write_config_byte(dev, PCI_INTERRUPT_LINE, dev->irq);
  dev_info(&dev->dev,"Succesfully requested IRQ #%d", dev->irq);

  bk_ptr->num_handled_interrupts = 0;
  bk_ptr->num_undelivered_signals = 0;

  /* Enable interrupts */
  //unmask_irq(bk_ptr);

  return 0;
}


void release_irq (struct pci_dev *dev, void *bk_ptr) {

  int num_usignals;

  /* Disable interrupts before going away. If something bad happened in
   * user space and the user program crashes, the interrupt assigned to the device
   * will be freed (on automatic close()) call but the device will continue
   * generating interrupts. Soon the kernel will notice, complain, and bring down
   * the whole system. */
  mask_irq(bk_ptr);

  dev_info(&dev->dev, "Freeing IRQ %d", dev->irq);
  free_irq (dev->irq, bk_ptr);

  dev_info(&dev->dev,"Handled %d interrupts",((struct altera_pcie_dma_bookkeep*)bk_ptr)->num_handled_interrupts);

  num_usignals = ((struct altera_pcie_dma_bookkeep*)bk_ptr)->num_undelivered_signals;
  if (num_usignals > 0) {
    dev_info(&dev->dev, "Number undelivered signals is %d", num_usignals);
  }

  /* Perform software reset on the FPGA.
   * If the host is killed after launching a kernel but before the kernel
   * finishes, the FPGA will keep sending "kernel done" interrupt. That might
   * kill a *new* host before it can do anything.
   *
   * WARNING: THIS RESET LOGIC IS ALSO IN THE HAL/PCIE.
   *          IF YOU CHANGE IT, UPDATE THE HAL AS WELL!!! */
  dev_info(&dev->dev, "Reseting kernel on FPGA");
  #if USE_MSI
    pci_disable_msi (dev);
  #endif
  mask_irq(bk_ptr);
}


/////////////////////// end  pxx //////////////////////////////////////


static int scan_bars(struct altera_pcie_dma_bookkeep *bk_ptr, struct pci_dev *dev)
{
    int i;
    for (i = 0; i < ALTERA_PCIE_BAR_NUM; i++) {
        unsigned long bar_start = pci_resource_start(dev, i);
        unsigned long bar_end = pci_resource_end(dev, i);
        unsigned long bar_flags = pci_resource_flags(dev, i);
        bk_ptr->bar_length[i] = pci_resource_len(dev, i);
        dev_info(&dev->dev, "BAR[%d] 0x%08lx-0x%08lx flags 0x%08lx, length %d", i, bar_start, bar_end, bar_flags, (int)bk_ptr->bar_length[i]);
    }
    return 0;
}

static int __init map_bars(struct altera_pcie_dma_bookkeep *bk_ptr, struct pci_dev *dev)
{
    int i;
    for (i = 0; i < ALTERA_PCIE_BAR_NUM; i++) {
        unsigned long bar_start = pci_resource_start(dev, i);
        bk_ptr->bar_length[i] = pci_resource_len(dev, i);
        if (!bk_ptr->bar_length[i]) {
            bk_ptr->bar[i] = NULL;
            continue;
        }
        bk_ptr->bar[i] = ioremap(bar_start, bk_ptr->bar_length[i]);
        if (!bk_ptr->bar[i]) {
            dev_err(&dev->dev, "could not map BAR[%d]", i);
            return -1;
        } else
            dev_info(&dev->dev, "BAR[%d] mapped to 0x%p, length %lu", i, bk_ptr->bar[i], (long unsigned int)bk_ptr->bar_length[i]);
    }
    return 0;
}

static void unmap_bars(struct altera_pcie_dma_bookkeep *bk_ptr, struct pci_dev *dev)
{
    int i;
    for (i = 0; i < ALTERA_PCIE_BAR_NUM; i++) {
        if (bk_ptr->bar[i]) {
            pci_iounmap(dev, bk_ptr->bar[i]);
            bk_ptr->bar[i] = NULL;
        }
    }
}

static int __init altera_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    int rc = 0;
    struct altera_pcie_dma_bookkeep *bk_ptr = NULL;
    char device_path[100];

    bk_ptr = kzalloc(sizeof(struct altera_pcie_dma_bookkeep), GFP_KERNEL);
    if (!bk_ptr)
        goto err_bk_alloc;

    bk_ptr->pci_dev = dev;
    pci_set_drvdata(dev, bk_ptr);

    rc = init_chrdev(bk_ptr);
    if (rc) {
        dev_err(&dev->dev, "init_chrdev() failed\n");
        goto err_initchrdev;
    }
    rc = pci_enable_device(dev);
    if (rc) {
        dev_err(&dev->dev, "pci_enable_device() failed\n");
        goto err_enable;
    } else {
        dev_info(&dev->dev, "pci_enable_device() successful");
    }
    rc = pci_request_regions(dev, ALTERA_PCIE_DRIVER_NAME);
    if (rc) {
        dev_err(&dev->dev, "pci_request_regions() failed\n");
        goto err_regions;
    }
    pci_set_master(dev);

   if (init_irq (bk_ptr->pci_dev, bk_ptr)) {
    dev_err(&bk_ptr->pci_dev->dev, "Could not allocate IRQ!");
  }

    scan_bars(bk_ptr, dev);
    map_bars(bk_ptr, dev);
    bk_ptr->rw_bar_no = 0;

    // waitqueue for user process
    init_waitqueue_head(&bk_ptr->wait_q);
    
    bk_ptr->lite_table_rd_cpu_virt_addr = ((struct lite_dma_desc_table *)pci_alloc_consistent(dev, sizeof(struct lite_dma_desc_table), &bk_ptr->lite_table_rd_bus_addr));
    if (!bk_ptr->lite_table_rd_cpu_virt_addr) {
        rc = -ENOMEM;
        goto err_rd_table;
    }
    bk_ptr->lite_table_rd_phys_addr = virt_to_phys((void *)bk_ptr->lite_table_rd_cpu_virt_addr);
    iowrite32(((dma_addr_t)bk_ptr->lite_table_rd_bus_addr)>>32, bk_ptr->bar[0] + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_RC_HIGH_SRC_ADDR);
    iowrite32((dma_addr_t)bk_ptr->lite_table_rd_bus_addr, bk_ptr->bar[0] + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_RC_LOW_SRC_ADDR);
    iowrite32(RD_CTRL_BUF_BASE_HI, bk_ptr->bar[0] + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_CTRL_HIGH_DEST_ADDR);
    iowrite32(RD_CTRL_BUF_BASE_LOW, bk_ptr->bar[0] + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_CTLR_LOW_DEST_ADDR);
    iowrite32(1, bk_ptr->bar[0] + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_RD_CONTROL);
    bk_ptr->lite_table_wr_cpu_virt_addr = ((struct lite_dma_desc_table *)pci_alloc_consistent(dev, sizeof(struct lite_dma_desc_table), &bk_ptr->lite_table_wr_bus_addr));
    if (!bk_ptr->lite_table_wr_cpu_virt_addr) {
        rc = -ENOMEM;
        goto err_wr_table;
    }
    bk_ptr->lite_table_wr_phys_addr = virt_to_phys((void *)bk_ptr->lite_table_wr_cpu_virt_addr);
    iowrite32(((dma_addr_t)bk_ptr->lite_table_wr_bus_addr)>>32, bk_ptr->bar[0] + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_WR_RC_HIGH_SRC_ADDR);
    iowrite32((dma_addr_t)bk_ptr->lite_table_wr_bus_addr, bk_ptr->bar[0] + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_WR_RC_LOW_SRC_ADDR);
    iowrite32(WR_CTRL_BUF_BASE_HI, bk_ptr->bar[0] + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_WR_CTRL_HIGH_DEST_ADDR);
    iowrite32(WR_CTRL_BUF_BASE_LOW, bk_ptr->bar[0] + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_WR_CTLR_LOW_DEST_ADDR);
    iowrite32(1, bk_ptr->bar[0] + DESC_CTRLLER_BASE + ALTERA_LITE_DMA_WR_CONTROL);
    bk_ptr->numpages = (PAGE_SIZE >= MAX_NUM_DWORDS*4) ? 1 : (int)((MAX_NUM_DWORDS*4)/PAGE_SIZE);
    bk_ptr->rp_rd_buffer_virt_addr = pci_alloc_consistent(dev, PAGE_SIZE*bk_ptr->numpages, &bk_ptr->rp_rd_buffer_bus_addr);
    if (!bk_ptr->rp_rd_buffer_virt_addr) {
        rc = -ENOMEM;
        goto err_rd_buffer;
    }
    bk_ptr->rp_rd_buffer_phys_addr = virt_to_phys((void *)bk_ptr->rp_rd_buffer_virt_addr);
    bk_ptr->rp_wr_buffer_virt_addr = pci_alloc_consistent(dev, PAGE_SIZE*bk_ptr->numpages, &bk_ptr->rp_wr_buffer_bus_addr);
    if (!bk_ptr->rp_wr_buffer_virt_addr) {
        rc = -ENOMEM;
        goto err_wr_buffer;
    }
    bk_ptr->rp_wr_buffer_phys_addr = virt_to_phys((void *)bk_ptr->rp_wr_buffer_virt_addr);

    sprintf(device_path, "%s%d", ALTERA_PCIE_DEVFILE, MINOR(bk_ptr->cdevno));
    bk_ptr->dev_class = class_create(THIS_MODULE, device_path);
    rc = IS_ERR(bk_ptr->dev_class);
    if (rc) {
        dev_err(&dev->dev, "dev_class create error\n");
        goto err_class;
    }

    bk_ptr->device = device_create(bk_ptr->dev_class, NULL, bk_ptr->cdevno, NULL, device_path);
    if (IS_ERR(bk_ptr->device)) {
        dev_err(&dev->dev, "device create error!\n");
        goto err_device;
    }

    return 0;

    // error clean up
err_device:
    dev_err(&dev->dev, "goto err_device");
    class_destroy(bk_ptr->dev_class);
err_class:
    dev_err(&dev->dev, "goto err_class");
    pci_free_consistent(dev, PAGE_SIZE*bk_ptr->numpages, bk_ptr->rp_wr_buffer_virt_addr, bk_ptr->rp_wr_buffer_bus_addr);
err_wr_buffer:
    dev_err(&dev->dev, "goto err_wr_buffer");
    pci_free_consistent(dev, PAGE_SIZE*bk_ptr->numpages, bk_ptr->rp_rd_buffer_virt_addr, bk_ptr->rp_rd_buffer_bus_addr);
err_rd_buffer:
    dev_err(&dev->dev, "goto err_rd_buffer");
    pci_free_consistent(dev, sizeof(struct lite_dma_desc_table), bk_ptr->lite_table_wr_cpu_virt_addr, bk_ptr->lite_table_wr_bus_addr);
err_wr_table:
    dev_err(&dev->dev, "goto err_wr_table");
    pci_free_consistent(dev, sizeof(struct lite_dma_desc_table), bk_ptr->lite_table_rd_cpu_virt_addr, bk_ptr->lite_table_rd_bus_addr);
err_rd_table:
    dev_err(&dev->dev, "goto err_rd_table");
err_irq:
    dev_err(&dev->dev, "goto err_regions");
err_dma_mask:
    dev_err(&dev->dev, "goto err_dma_mask");
    pci_release_regions(dev);
err_regions:
    dev_err(&dev->dev, "goto err_irq");
    pci_disable_device(dev);
err_enable:
    dev_err(&dev->dev, "goto err_enable");
    unregister_chrdev_region(bk_ptr->cdevno, 1);
    device_minor_count--;
err_initchrdev:
    dev_err(&dev->dev, "goto err_initchrdev");
    kfree(bk_ptr);
err_bk_alloc:
    dev_err(&dev->dev, "goto err_bk_alloc");
    return rc;
}

static void __exit altera_pci_remove(struct pci_dev *dev)
{
    struct altera_pcie_dma_bookkeep *bk_ptr = NULL;
    bk_ptr = pci_get_drvdata(dev);
    cdev_del(&bk_ptr->cdev);
    unregister_chrdev_region(bk_ptr->cdevno, 1);
    device_minor_count--;
    pci_disable_device(dev);
  #if USE_MSI
    //pci_disable_msi(dev);
    release_irq(dev,bk_ptr);
  #endif   
    unmap_bars(bk_ptr, dev);
    pci_release_regions(dev); 
        
    if (bk_ptr->irq_line >= 0) { 
      printk(KERN_DEBUG "Freeing IRQ #%d", bk_ptr->irq_line);
      free_irq(bk_ptr->irq_line, (void *)bk_ptr);        
    }
    pci_free_consistent(dev, sizeof(struct lite_dma_desc_table), bk_ptr->lite_table_rd_cpu_virt_addr, bk_ptr->lite_table_rd_bus_addr);
    pci_free_consistent(dev, sizeof(struct lite_dma_desc_table), bk_ptr->lite_table_wr_cpu_virt_addr, bk_ptr->lite_table_wr_bus_addr);
    pci_free_consistent(dev, PAGE_SIZE*bk_ptr->numpages, bk_ptr->rp_rd_buffer_virt_addr, bk_ptr->rp_rd_buffer_bus_addr);
    pci_free_consistent(dev, PAGE_SIZE*bk_ptr->numpages, bk_ptr->rp_wr_buffer_virt_addr, bk_ptr->rp_wr_buffer_bus_addr);
        

    device_unregister(bk_ptr->device);
    class_destroy(bk_ptr->dev_class);

    kfree(bk_ptr);
    dev_err(&dev->dev, ": altera_pcie_remove(), " __DATE__ " " __TIME__ "\n");
}

static struct pci_device_id pci_ids[] = {
    { 0 },
    { 0 }
};

static struct pci_driver dma_driver_ops = {
    .name = ALTERA_PCIE_DRIVER_NAME,
    .id_table = pci_ids,
    .probe = altera_pci_probe,
    .remove = altera_pci_remove,
};

static int __init altera_pcie_init(void)
{
    int rc = 0;

    printk(KERN_DEBUG ALTERA_PCIE_DRIVER_NAME ": altera_pcie_init(), " __DATE__ " " __TIME__ "\n");

    pci_ids[0].vendor = vendor_id;
    pci_ids[0].device = device_id;
    pci_ids[0].subvendor = PCI_ANY_ID;
    pci_ids[0].subdevice = PCI_ANY_ID;

    rc = pci_register_driver(&dma_driver_ops);
    if (rc) {
        printk(KERN_ERR ALTERA_PCIE_DRIVER_NAME ": PCI driver registration failed\n");
        goto exit;
    }

exit:
    return rc;
}

static void __exit altera_pcie_exit(void)
{
    pci_unregister_driver(&dma_driver_ops);
}

#ifdef MEASURE_TIME
static int diff_timeval(struct timeval *result, struct timeval *t2, struct timeval *t1)
{
    long int diff = (t2->tv_usec + 1000000 * t2->tv_sec) - (t1->tv_usec + 1000000 * t1->tv_sec);
    result->tv_sec = diff / 1000000;
    result->tv_usec = diff % 1000000;
    return (diff < 0);
}
#endif

module_init(altera_pcie_init);
module_exit(altera_pcie_exit);

MODULE_AUTHOR("Michael Chen <micchen@altera.com>");
MODULE_DESCRIPTION("256b DMA Driver");
MODULE_VERSION(ALTERA_PCIE_DRIVER_VERSION);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DEVICE_TABLE(pci, pci_ids);

