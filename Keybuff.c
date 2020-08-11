/* Keybuff.c
Course: COMP 3430 A01
Assignment: Assignment 3 question 2
Instructor: Micheal Zapp
Author: Pratik Patel, 7837299
Purpose: Linux kernel module that implements a keyboard driver that supports shift and plain keys
*/
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h> /* We want an interrupt */
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Pratik Patel");


//-------------------------------------------------------------------------------------
// CONSTANTS and TYPES
//------------------------------------------------------------------------------------

/* Keyboard Controller Registers on normal PCs. TAKEN FROM kdb_keyboard.c*/

#define KBD_STATUS_REG 0x64 /* Status register (R) */
#define KBD_DATA_REG 0x60	/* Keyboard data register (R/W) */

#define KBD_STAT_OBF 0x01 /* Keyboard output buffer full */

//this should be 128 but i went with 256
#define NR_KEYS 256
#define MAX_NR_KEYMAPS 256

//maximum buffer size
#define MAX_BUFFER_SIZE 16
//-----------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------
// VARIABLES
//-------------------------------------------------------------------------------------
//the circular queue implementation
static char processBuffer[MAX_BUFFER_SIZE];
//starting index in the queue
static int startIndex = 0;
//ending index in the queue
static int endIndex = 0;
//buffer count
static int buffCount = 0;
//for irqhandler
static int irqHandled;

//used my own struct instead of the work_struct pointer to pass the data to a worker
struct myWorker
{
    // stores the scanned key from the keybored
    char scan_code;
    // the worker struct to get and assign the task
    struct work_struct task;
};

//required to create and initalize the /proc/keybuff
static struct proc_dir_entry *ent;

//used to check keyboard I/O
static int kbd_exists;
static int kbd_last_ret;

//this will be my worker pointer that will be used by the IRQ handler
static struct myWorker *workerPtr;

//for locking/unlocking
static spinlock_t my_lock;
//------------------------------------------------------------------------------------------

//Plain Keys look up table taken from defkeymap.c_shipped
u_short plain_map[NR_KEYS] ={
    0xf200, 0xf01b, 0xf031, 0xf032, 0xf033, 0xf034, 0xf035, 0xf036,
    0xf037, 0xf038, 0xf039, 0xf030, 0xf02d, 0xf03d, 0xf07f, 0xf009,
    0xfb71, 0xfb77, 0xfb65, 0xfb72, 0xfb74, 0xfb79, 0xfb75, 0xfb69,
    0xfb6f, 0xfb70, 0xf05b, 0xf05d, 0xf201, 0xf702, 0xfb61, 0xfb73,
    0xfb64, 0xfb66, 0xfb67, 0xfb68, 0xfb6a, 0xfb6b, 0xfb6c, 0xf03b,
    0xf027, 0xf060, 0xf700, 0xf05c, 0xfb7a, 0xfb78, 0xfb63, 0xfb76,
    0xfb62, 0xfb6e, 0xfb6d, 0xf02c, 0xf02e, 0xf02f, 0xf700, 0xf30c,
    0xf703, 0xf020, 0xf207, 0xf100, 0xf101, 0xf102, 0xf103, 0xf104,
    0xf105, 0xf106, 0xf107, 0xf108, 0xf109, 0xf208, 0xf209, 0xf307,
    0xf308, 0xf309, 0xf30b, 0xf304, 0xf305, 0xf306, 0xf30a, 0xf301,
    0xf302, 0xf303, 0xf300, 0xf310, 0xf206, 0xf200, 0xf03c, 0xf10a,
    0xf10b, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200,
    0xf30e, 0xf702, 0xf30d, 0xf01c, 0xf701, 0xf205, 0xf114, 0xf603,
    0xf118, 0xf601, 0xf602, 0xf117, 0xf600, 0xf119, 0xf115, 0xf116,
    0xf11a, 0xf10c, 0xf10d, 0xf11b, 0xf11c, 0xf110, 0xf311, 0xf11d,
    0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200,
};

// Shift Keys look up table taken from defkeymap.c_shipped
u_short shift_map[NR_KEYS] ={
    0xf200, 0xf01b, 0xf021, 0xf040, 0xf023, 0xf024, 0xf025, 0xf05e,
    0xf026, 0xf02a, 0xf028, 0xf029, 0xf05f, 0xf02b, 0xf07f, 0xf009,
    0xfb51, 0xfb57, 0xfb45, 0xfb52, 0xfb54, 0xfb59, 0xfb55, 0xfb49,
    0xfb4f, 0xfb50, 0xf07b, 0xf07d, 0xf201, 0xf702, 0xfb41, 0xfb53,
    0xfb44, 0xfb46, 0xfb47, 0xfb48, 0xfb4a, 0xfb4b, 0xfb4c, 0xf03a,
    0xf022, 0xf07e, 0xf700, 0xf07c, 0xfb5a, 0xfb58, 0xfb43, 0xfb56,
    0xfb42, 0xfb4e, 0xfb4d, 0xf03c, 0xf03e, 0xf03f, 0xf700, 0xf30c,
    0xf703, 0xf020, 0xf207, 0xf10a, 0xf10b, 0xf10c, 0xf10d, 0xf10e,
    0xf10f, 0xf110, 0xf111, 0xf112, 0xf113, 0xf213, 0xf203, 0xf307,
    0xf308, 0xf309, 0xf30b, 0xf304, 0xf305, 0xf306, 0xf30a, 0xf301,
    0xf302, 0xf303, 0xf300, 0xf310, 0xf206, 0xf200, 0xf03e, 0xf10a,
    0xf10b, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200,
    0xf30e, 0xf702, 0xf30d, 0xf200, 0xf701, 0xf205, 0xf114, 0xf603,
    0xf20b, 0xf601, 0xf602, 0xf117, 0xf600, 0xf20a, 0xf115, 0xf116,
    0xf11a, 0xf10c, 0xf10d, 0xf11b, 0xf11c, 0xf110, 0xf311, 0xf11d,
    0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200,
};

//store the shift and plain keys as those are the only ones we're supporting
ushort *key_maps[MAX_NR_KEYMAPS] ={ plain_map, shift_map };

//-------------------------------------------------------------------------------------
// FUNCTIONS
//-------------------------------------------------------------------------------------
/* kdb_get_kdb_char()
    This method is created on the kdb_keyboard.c code is for the generic keyboard used for
    debugging in the kernel,  i modified the code to support only the plain and shift keys.
    it returns an int (hex) value of the key that was pressed */
int kdb_get_kdb_char(void)
{
    int scancode, scanstatus;
    static int shift_key;
    static int shift_lock;
    u_short keychar;

    if (inb(KBD_STATUS_REG) == 0xff && inb(KBD_DATA_REG) == 0xff)
    {
        printk(KERN_INFO "CRASHED AT 1ST IF");
        kbd_exists = 0;
        return -1;
    }
    kbd_exists = 1;

    scancode = inb(KBD_DATA_REG);
    scanstatus = inb(KBD_STATUS_REG);

    if (((scancode & 0x7f) == 0x2a) || ((scancode & 0x7f) == 0x36))
    {
        /*
        * Next key may use shift table
        */
        if ((scancode & 0x80) == 0)
            shift_key = 1;
        else
            shift_key = 0;
        return -1;
    }

    if ((scancode & 0x80) != 0)
    {
        if (scancode == 0x9c)
            kbd_last_ret = 0;
        return -1;
    }

    scancode &= 0x7f;

    if (scancode == 0xe0)
        return -1;

    /*
    * For Japanese 86/106 keyboards
    * 	See comment in drivers/char/pc_keyb.c.
    * 	- Masahiro Adegawa
    */
    if (scancode == 0x73)
        scancode = 0x59;
    else if (scancode == 0x7d)
        scancode = 0x7c;

    if (!shift_lock && !shift_key)
    {
        keychar = plain_map[scancode];
    }
    else if ((shift_lock || shift_key) && key_maps[1])
    {
        keychar = key_maps[1][scancode];
    }
    else
    {
        keychar = 0x0020;
        printk(KERN_INFO "Unknown state/scancode (%d)\n", scancode);
    }
    keychar &= 0x0fff;
    if (keychar == '\t')
        keychar = ' ';

    if (scancode == 0x1c)
    {
        kbd_last_ret = 1;
        return 13;
    }

    return keychar & 0xff;
}

/* gotChar()
This method is my worker method it checks whether the key was stored in the buffer or not
and also does the locking and unlocking for mutual exculsion implementation
*/
static void gotChar(struct work_struct *work)
{
    struct myWorker *myptr = container_of(work, struct myWorker, task);
    printk(KERN_INFO "Scan Code %c \n", myptr->scan_code);

    //if(count != MAX_BUFFER_SIZE)

    spin_lock(&my_lock);
    if (buffCount == MAX_BUFFER_SIZE)
    {
        printk(KERN_INFO "Queue is Full..I will try adding..\n");
    }
    else
    {
        printk(KERN_INFO "Queue has space lets add..\n");
        processBuffer[startIndex] = myptr->scan_code;
        startIndex = (startIndex + 1) % MAX_BUFFER_SIZE;
        buffCount++;
        printk(KERN_INFO "Count is %d \n", buffCount);
    }
    spin_unlock(&my_lock);
    kfree(myptr);
}

/*irq_handler()
    this routine is the interrupt handler implementation for my keyboard driver
*/
static irqreturn_t irq_handler(int irg, void *dev_id)
{

    char test;

    int scanCode = 0;
    /*scan the keyboard keys and print out on the kernel which
    key was pressed. note this will return -1 after each key pressed
    as we are making sure the key is released. */
    scanCode = kdb_get_kdb_char();
    if (scanCode < 0)
    {
        //printk(KERN_INFO "Releasing the key %c \n", (char)scanCode);
    }
    else
    {
        printk(KERN_INFO "Key pressed is %c \n", (char)scanCode);
        workerPtr = (struct myWorker *)kmalloc(sizeof(struct myWorker), GFP_ATOMIC);

        //cast the scanned key to a char
        test = (char)scanCode;
        workerPtr->scan_code = test;

        //initialize the worker
        INIT_WORK(&workerPtr->task, gotChar);

        //give the worker some work on the queue
        schedule_work(&workerPtr->task);
    }

    return IRQ_HANDLED;
}


/* myread()
    this read routine takes the scanned keyboard char and prints it to the user, implented
    mutex lock/unlocking with spin locks.
*/
static ssize_t myread(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    char temp[MAX_BUFFER_SIZE];
    int buffLen = 0;

    printk(KERN_INFO "HELLO READ ROUTINE\n");
    printk(KERN_INFO "HELLO BUFFER start SIZE IS %d \n", buffCount);


    spin_lock(&my_lock);
    while (buffCount > 0)
    {

        temp[buffLen] = processBuffer[endIndex];
        buffLen++;

        endIndex = (endIndex + 1) % MAX_BUFFER_SIZE;
        buffCount--;


        printk(KERN_INFO "HELLO READ buffer end is %d \n", buffCount);


    }
    spin_unlock(&my_lock);
    if (copy_to_user(ubuf, temp, buffLen))
    {
        return -EFAULT;
    }


    *ppos = buffLen;
    return buffLen;
}



static struct file_operations myops =
{
    .owner = THIS_MODULE,
    .read = myread,

};

/* simple_init
initilaization method that initializes our proc file, spin locks and the interrupt handler
*/
static int simple_init(void)
{

    ent = proc_create("keybuff", 0660, NULL, &myops);
    spin_lock_init(&my_lock);
    printk(KERN_ALERT "hello Keyboard logger...\n");
    irqHandled = request_irq(1, irq_handler, IRQF_SHARED, "test_keyboard_irq_handler", (void *)(irq_handler));
    return 0;
}

/* simple_cleamup
    This routine is called when we are doing clean up after we are done with the module
*/
static void simple_cleanup(void)
{
    proc_remove(ent);
    //No need to restart the VM eveytime
    free_irq(1, irq_handler);
    printk(KERN_ALERT "BYE Keyboard Logger Exiting...\n");
}

//intialize and create the module
module_init(simple_init);
//once done with the module clean up
module_exit(simple_cleanup);
