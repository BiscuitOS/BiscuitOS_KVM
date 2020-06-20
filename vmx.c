/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

static int __init vmx_init_bs(void)
{
	printk("Intel-VMX init-stage.\n");
	return 0;
}

static void __exit vmx_exit_bs(void)
{
}

module_init(vmx_init_bs);
module_exit(vmx_exit_bs);

MODULE_AUTHOR("BiscuitOS Copy");
MODULE_LICENSE("GPL");
