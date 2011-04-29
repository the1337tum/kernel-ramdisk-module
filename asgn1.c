
/**
 * File: asgn1.c
 * Date: 31/03/2011
 * Author: Zhiyi Huang
 * Modified by: Tum.
 * Version: 0.2
 *
 * This is a module which serves as a virtual ramdisk which disk size is
 * limited by the amount of memory available and serves as the requirement for
 * COSC440 assignment 1 in 2011.
 *
 * Note: multiple devices and concurrent modules are not supported in this
 *       version.
 */
 
/* This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/device.h>
#include <linux/ioctl.h>

#define MYDRVR_NAME "asgn1"
#define MYDRVR_BASE 'k'

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tum.");
MODULE_DESCRIPTION("COSC440 asgn1");


int major = 0;
dev_t devno;                       // device number 
struct cdev asgn1_cdev;            // device
static struct class *asgn1_class;  // udev class
struct proc_dir_entry *asgn1_proc; // proc entry

atomic_t num_connections = ATOMIC_INIT(0);
atomic_t max_connections = ATOMIC_INIT(1);

// The page list, for dynamic memory management
struct list_head mem_list;

int num_pages = 0;
int page_offset = 0;

struct page_node {
    struct list_head list;
    struct page *page;
};

int ramdisk_used = 0;

#define SET_NPROC_OP 1
#define MYIOC_TYPE 1
#define ASIGN_SET_NPROC _IOW(MYIOC_TYPE, SET_NPROC_OP, int)
static int asgn1_ioctl(struct inode *inode, struct file *file, unsigned int cmd, void *argp) {
    if (_IOC_TYPE(cmd) != MYDRVR_BASE)  return -EINVAL;

    switch (cmd) {
    case ASIGN_SET_NPROC:
        if (*(int*)(argp) < atomic_read(&num_connections)) {
            atomic_set(&max_connections, *(int*)(argp));
            return 0;
        } else {
            return -EINVAL;
        }
    }
    return -ENOTTY;
}

int asgn1_open(struct inode *inode, struct file *filp) {
    struct page_node *node;
    struct page_node *tmp;

    if (atomic_read(&num_connections) < atomic_read(&max_connections))
        atomic_inc(&num_connections);
    else
        return -EBUSY;
    
    if (filp->f_flags == O_WRONLY) {
        list_for_each_entry_safe(node, tmp, &mem_list, list) {
            list_del(&node->list);
            free_page(page_to_pfn(node->page));
            kfree(node);
        }
        num_pages = 0;
    }

    return 0;
}

int asgn1_release (struct inode *inode, struct file *filp) {
    if (atomic_read(&num_connections) > 0)
        atomic_dec(&num_connections);

    return 0;
}

static loff_t asgn1_lseek (struct file *filep, loff_t offset, int orig) {
    loff_t testpos;
    int ramdisk_size = num_pages * PAGE_SIZE;

    switch (orig) {
    case SEEK_SET:
        testpos = offset;
        break;
    case SEEK_CUR:
        testpos = filep->f_pos + offset;
        break;
    case SEEK_END:
        testpos = ramdisk_size + offset;
        break;
    default:
        return -EINVAL;
    }
    testpos = testpos < ramdisk_size ? testpos : ramdisk_size;
    testpos = testpos >= 0 ? testpos : 0;
    filep->f_pos = testpos;
    return testpos;
}

// A somewhat useless function. It simply checks that no data was mutated upon copy
ssize_t user_copy(unsigned long (*callback)(void*, const void*, unsigned long), void *to, const void *from, unsigned long size) {
    do
        if (callback(to, from, size)) return -EINVAL;
    while (memcmp(to, from, size));
    return 0;
}

ssize_t asgn1_read(struct file *filep, char __user *user_buffer, size_t count, loff_t *f_pos) {
    size_t size_read = 0;
    
    // cursors
    struct page_node *node;
    int to_read;
    int ptr = 0;

    printk(KERN_INFO "Entering read");
    if (filep->f_pos == ramdisk_used)
        return 0;

    list_for_each_entry(node, &mem_list, list) {
        if (ptr + PAGE_SIZE < *f_pos) {
            // move to the start
            if (ptr < *f_pos) {
                ptr += PAGE_SIZE;   
                continue;
            }
            // read the first partial page 
            to_read = *f_pos - ptr;
            if (user_copy(copy_to_user, user_buffer, page_address(node->page) + page_offset, to_read)) return -EINVAL;
        } else if (count - size_read < PAGE_SIZE) {
            // read the last page
            to_read = count - size_read;
            if (user_copy(copy_to_user, user_buffer, page_address(node->page), to_read)) return -EINVAL;
            size_read += to_read;
            break;
        } else {
            // read middle pages
            to_read = PAGE_SIZE;
            if (user_copy(copy_to_user, user_buffer, page_address(node->page), to_read)) return -EINVAL;
        }
        size_read += to_read;
        ptr += to_read;
    }
    filep->f_pos = filep->f_pos + size_read < ramdisk_used ? filep->f_pos + size_read : ramdisk_used;

    printk(KERN_INFO "Read %d bytes to device", size_read);
    return size_read;
}

struct page_node *create_page() {
    struct page_node *node = (struct page_node*) kmalloc(sizeof(struct page_node), GFP_KERNEL);
    if (node == NULL)
        return NULL;
    
    INIT_LIST_HEAD(&(node->list));
    node->page = alloc_page(GFP_KERNEL);
    if (node->page == NULL) {
        kfree(node);
        return NULL;
    }
    list_add_tail(&(node->list), &mem_list);
    
    num_pages++;
    return node;
}

ssize_t asgn1_write(struct file *filep, const char __user *user_buffer, size_t count, loff_t *f_pos) {
    size_t size_written = 0;

    // cursors
    struct page_node *node;
    size_t to_write = 0;
    int ptr = 0;
    
    printk(KERN_INFO "Entering write");

    // ensure there are enough pages
    while (num_pages < ((*f_pos + count) / PAGE_SIZE))
        if(create_page() == NULL) return -ENOMEM;
    
    list_for_each_entry(node, &mem_list, list) {
        if (ptr + PAGE_SIZE < *f_pos) {
            // move to the start
            if (ptr < *f_pos) {
                ptr += PAGE_SIZE;   
                continue;
            }
            // write the first partial page 
            to_write = *f_pos - ptr;
            if (user_copy(copy_from_user, page_address(node->page) + page_offset, user_buffer, to_write)) return -EINVAL;
        } else if (count - size_written < PAGE_SIZE) {
            // write the last page
            to_write = count - size_written;
            if (user_copy(copy_from_user, page_address(node->page), user_buffer, to_write)) return -EINVAL;
            size_written += to_write;
            break;
        } else {
            // write middle pages
            to_write = PAGE_SIZE;
            if (user_copy(copy_from_user, page_address(node->page), user_buffer, to_write)) return -EINVAL;
        }
        size_written += to_write;
        ptr += to_write;
    }
    page_offset = to_write;
    filep->f_pos += size_written;
    ramdisk_used += size_written;

    printk(KERN_INFO "Wrote %d bytes to device", size_written);
    return size_written;
}

/**
 * Displays information about current status of the module,
 * which helps debugging.
 */
int asgn1_read_procmem(char *buf, char **start, off_t offset, int count, int *eof, void *data) {
    return sprintf(buf, "Number of pages: %d\t Ramdisk size: %ld\n", num_pages, (PAGE_SIZE * num_pages));
}

#define MMAP_DEV_CMD_GET_BUFSIZE 1
static int asgn1_mmap (struct file *filp, struct vm_area_struct *vma) {
    int page = 0;
    struct page_node *node;
    list_for_each_entry(node, &mem_list, list) {
        if (page >= vma->vm_pgoff)
            if (remap_pfn_range(vma, vma->vm_start + PAGE_SIZE * (page - vma->vm_pgoff), page_to_pfn(node->page), PAGE_SIZE, vma->vm_page_prot))
                return -EAGAIN;
        page++;
    }
    return 0;
}


struct file_operations asgn1_fops = {
  .owner = THIS_MODULE,
  .read = asgn1_read,
  .write = asgn1_write,
  .ioctl = asgn1_ioctl,
  .open = asgn1_open,
  .mmap = asgn1_mmap,
  .release = asgn1_release,
  .llseek = asgn1_lseek
};

/**
 * Initialise the module and create the master device
 */
int __init asgn1_init_module(void){
    int rv; 
	devno = MKDEV(major, MYDRVR_BASE);

    printk(KERN_INFO "Registering device");
	if(major) {
		rv = register_chrdev_region(devno, 1, MYDRVR_NAME);
		if(rv < 0){
			printk(KERN_WARNING "Can't use the major number %d; try atomatic allocation...\n", major);
			rv = alloc_chrdev_region(&devno, 0, 1, MYDRVR_NAME);
			major = MAJOR(devno);
		}
	} else {
		rv = alloc_chrdev_region(&devno, 0, 1, MYDRVR_NAME);
		major = MAJOR(devno);
	}
    if(rv < 0) return rv;

    printk(KERN_INFO "Initilising device");
    cdev_init(&asgn1_cdev, &asgn1_fops);
    rv = cdev_add(&asgn1_cdev, devno, 1);
	if (rv) printk(KERN_WARNING "Error %d adding device temp", rv);

    printk(KERN_INFO "Creating udev entry");
    asgn1_class = class_create(THIS_MODULE, MYDRVR_NAME);
    device_create(asgn1_class, NULL, devno, "%s", MYDRVR_NAME);
    
    printk(KERN_INFO "Creating list");
    INIT_LIST_HEAD(&mem_list);
	if (create_page() == NULL) return -ENOMEM;

    printk(KERN_INFO "Creating proc entry");
    asgn1_proc = create_proc_entry("driver/asgn1", NULL, NULL);
    asgn1_proc->read_proc = asgn1_read_procmem;

	printk(KERN_INFO "Device %s created, MAJOR is %d\n",MYDRVR_NAME,  major);
    return 0;
}

/**
 * Finalise the module
 */
void __exit asgn1_exit_module(void){
    struct page_node *node;
    struct page_node *tmp;

    printk(KERN_INFO "Destroying list");
    list_for_each_entry_safe(node, tmp, &mem_list, list) {
        list_del(&node->list);
        free_page(page_to_pfn(node->page));
        kfree(node);
    }
    printk(KERN_INFO "Uninitilising device");
    device_destroy(asgn1_class, devno);
    printk(KERN_INFO "Removing udev entry");
    class_destroy(asgn1_class);
    printk(KERN_INFO "Unregistering device");
    unregister_chrdev_region(devno, 1);
    printk(KERN_INFO "Removing proc entry");
    remove_proc_entry("asgn1_proc", NULL);

    printk(KERN_INFO "Device %s destroyed\n", MYDRVR_NAME);
}

module_init(asgn1_init_module);
module_exit(asgn1_exit_module);

