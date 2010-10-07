#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/icmp.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/time.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/delay.h>
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/module.h>	/* Specifically, a module */
#include <linux/fs.h>
#include <asm/uaccess.h>	/* for get_user and put_user */

#include "chardev.h"
#define SUCCESS 0
#define DEVICE_NAME "char_dev"
#define BUF_LEN 80


int setup_skb_packet(struct sk_buff *skb, char * data, int len);
/* function prototypes */
int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len);


struct sk_buff *sock_buff;
struct iphdr *ip_header;
struct udphdr *udp_header;
static struct nf_hook_ops nfho;
struct sk_buff *udp_skb;
int times=0;
int txr_type=1;


/* 
 * Is the device open right now? Used to prevent
 * concurent access into the same device 
 */
static int Device_Open = 0;

/* 
 * The message the device will give when asked 
 */
static char Message[BUF_LEN];

/* 
 * How far did the process reading the message get?
 * Useful if the message is larger than the size of the
 * buffer we get to fill in device_read. 
 */
static char *Message_Ptr;

/* 
 * This is called whenever a process attempts to open the device file 
 */
static int device_open(struct inode *inode, struct file *file)
{
#ifdef DEBUG
	printk(KERN_INFO "device_open(%p)\n", file);
#endif

	/* 
	 * We don't want to talk to two processes at the same time 
	 */
	if (Device_Open)
		return -EBUSY;

	Device_Open++;
	/*
	 * Initialize the message 
	 */
	Message_Ptr = Message;
	try_module_get(THIS_MODULE);
	return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file)
{
#ifdef DEBUG
	printk(KERN_INFO "device_release(%p,%p)\n", inode, file);
#endif

	/* 
	 * We're now ready for our next caller 
	 */
	Device_Open--;

	module_put(THIS_MODULE);
	return SUCCESS;
}

/* 
 * This function is called whenever a process which has already opened the
 * device file attempts to read from it.
 */
static ssize_t device_read(struct file *file,	/* see include/linux/fs.h   */
			   char __user * buffer,	/* buffer to be
							 * filled with data */
			   size_t length,	/* length of the buffer     */
			   loff_t * offset)
{
	/* 
	 * Number of bytes actually written to the buffer 
	 */
	int bytes_read = 0;

#ifdef DEBUG
	printk(KERN_INFO "device_read(%p,%p,%d)\n", file, buffer, length);
#endif

	/* 
	 * If we're at the end of the message, return 0
	 * (which signifies end of file) 
	 */
	if (*Message_Ptr == 0)
		return 0;

	/* 
	 * Actually put the data into the buffer 
	 */
	while (length && *Message_Ptr) {

		/* 
		 * Because the buffer is in the user data segment,
		 * not the kernel data segment, assignment wouldn't
		 * work. Instead, we have to use put_user which
		 * copies data from the kernel data segment to the
		 * user data segment. 
		 */
		put_user(*(Message_Ptr++), buffer++);
		length--;
		bytes_read++;
	}

#ifdef DEBUG
	printk(KERN_INFO "Read %d bytes, %d left\n", bytes_read, length);
#endif

	/* 
	 * Read functions are supposed to return the number
	 * of bytes actually inserted into the buffer 
	 */
	return bytes_read;
}

/* 
 * This function is called when somebody tries to
 * write into our device file. 
 */
static ssize_t
device_write(struct file *file,
	     const char __user * buffer, size_t length, loff_t * offset)
{
	int i;

#ifdef DEBUG
	printk(KERN_INFO "device_write(%p,%s,%d)", file, buffer, length);
#endif

	for (i = 0; i < length && i < BUF_LEN; i++)
		get_user(Message[i], buffer + i);

	Message_Ptr = Message;

	/* 
	 * Again, return the number of input characters used 
	 */
	return i;
}

/* 
 * This function is called whenever a process tries to do an ioctl on our
 * device file. We get two extra parameters (additional to the inode and file
 * structures, which all device functions get): the number of the ioctl called
 * and the parameter given to the ioctl function.
 *
 * If the ioctl is write or read/write (meaning output is returned to the
 * calling process), the ioctl call returns the output of this function.
 *
 */
int device_ioctl(struct inode *inode,	/* see include/linux/fs.h */
		 struct file *file,	/* ditto */
		 unsigned int ioctl_num,	/* number and param for ioctl */
		 unsigned long ioctl_param)
{
	int i;
	char *temp;
	char ch;
	char *user_data;
	unsigned int user_data_len;
//	char *kernel_data;
//	kernel_data=kmalloc(100,0);

	/* 
	 * Switch according to the ioctl called 
	 */
	switch (ioctl_num) {
	case IOCTL_SET_MSG:
		/* 
		 * Receive a pointer to a message (in user space) and set that
		 * to be the device's message.  Get the parameter given to 
		 * ioctl by the process. 
		 */
		temp = (char *)ioctl_param;

		/* 
		 * Find the length of the message 
		 */
		get_user(ch, temp);
	//	for (i = 0; ch && i < BUF_LEN; i++, temp++)
	//		get_user(ch, temp);
		user_data=simple_strtoul(ioctl_param,NULL,10);
		if(txr_type==1) {
		user_data_len=simple_strtoul(ioctl_param+11,NULL,10);
		printk("pointer is %u and len %d\n", user_data , user_data_len+20);
		//copy_from_user(kernel_data,user_data,user_data_len);
		setup_skb_packet(udp_skb, user_data, user_data_len+20);
		txr_type++;
		}
		else {
			copy_from_user((udp_skb->tail)-20,user_data,20);
			printk("soft xmit %d %c size %d \n",dev_queue_xmit(udp_skb), *((udp_skb->data)+28),udp_skb->len); 
			txr_type=1;
		}
		//printk("passed content is %s\n",kernel_data);
		device_write(file, (char *)ioctl_param, 10, 0);
//		kfree(kernel_data);
		break;

	case IOCTL_GET_MSG:
		/* 
		 * Give the current message to the calling process - 
		 * the parameter we got is a pointer, fill it. 
		 */
		i = device_read(file, (char *)ioctl_param, 99, 0);

		/* 
		 * Put a zero at the end of the buffer, so it will be 
		 * properly terminated 
		 */
		put_user('\0', (char *)ioctl_param + i);
		break;

	case IOCTL_GET_NTH_BYTE:
		/* 
		 * This ioctl is both input (ioctl_param) and 
		 * output (the return value of this function) 
		 */
		return Message[ioctl_param];
		break;
	}

	return SUCCESS;
}

/* Module Declarations */

/* 
 * This structure will hold the functions to be called
 * when a process does something to the device we
 * created. Since a pointer to this structure is kept in
 * the devices table, it can't be local to
 * init_module. NULL is for unimplemented functions. 
 */
struct file_operations Fops = {
	.read = device_read,
	.write = device_write,
	.ioctl = device_ioctl,
	.open = device_open,
	.release = device_release,	/* a.k.a. close */
};

/* 
 * Initialize the module - Register the character device 
 */

#define DEFAULT_PORT 2325
#define CONNECT_PORT 16767
#define MODULE_NAME "ksocket"
//#define INADDR_SEND ((unsigned long int)0x7f000001) /* 127.0.0.1 */
#define INADDR_SEND ((unsigned long int)0xB010F680) /* 127.0.0.1 */
//#define INADDR_SEND INADDR_LOOPBACK





int send_arp_request(void) 
{ 
struct socket *arpsock; 
struct sockaddr sa; 
struct msghdr msg; 
struct iovec iov; 
mm_segment_t oldfs; 
int size = 0; 
int error = 0; 
char *warp_dev="eth0"; 
char dev[20]; 
char*buf="This is a message from kernel";

if ((error=sock_create(PF_INET, SOCK_PACKET, htons(ETH_P_ARP), 
&arpsock))<0) { 
printk(KERN_WARNING "Could not create a PF_PACKET SOCK_RAW Socket\n"); 
return (-1); 
} 

memset(&sa,0,sizeof(sa)); 
strcpy(dev,warp_dev); 
strncpy(sa.sa_data,dev,sizeof(sa.sa_data)); 

error = arpsock->ops->bind(arpsock,&sa,sizeof(sa)); 

if (error<0) 
{ 
printk(KERN_WARNING "Error binding socket"); 
return -1; 
} 

iov.iov_base = (char *)buf; 
iov.iov_len = (__kernel_size_t) strlen(buf); 

msg.msg_iov = &iov; 
msg.msg_iovlen = 1; 
msg.msg_control = NULL; 
msg.msg_controllen = 0; 
msg.msg_name = NULL; 
msg.msg_namelen = 0; 
msg.msg_flags = 0; 

oldfs = get_fs(); 
set_fs(KERNEL_DS); 
size = sock_sendmsg(arpsock,&msg,strlen(buf)); 
set_fs(oldfs); 

if (size < 0) 
printk(KERN_WARNING "sock_sendmsg error: %d\n",size); 

return 0; 

} 


long long timeval_diff(struct timeval *difference, struct timeval *end_time, struct timeval *start_time)
{
  struct timeval temp_diff;

  if(difference==NULL)
  {
    difference=&temp_diff;
  }

  difference->tv_sec =end_time->tv_sec -start_time->tv_sec ;
  difference->tv_usec=end_time->tv_usec-start_time->tv_usec;

  /* Using while instead of if below makes the code slightly more robust. */

  while(difference->tv_usec<0)
  {
    difference->tv_usec+=1000000;
    difference->tv_sec -=1;
  }

  return 1000000LL*difference->tv_sec+
                   difference->tv_usec;

} /* timeval_diff() */


static unsigned int hook_func(unsigned int hooknum,
	       		struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	if(times>=1) {
		return NF_ACCEPT;
	}
	sock_buff = skb; 

	if (!sock_buff) {
		return NF_ACCEPT;
	} else {
		ip_header = (struct iphdr *)skb_network_header(sock_buff);
		if (!ip_header) {
			return NF_ACCEPT;
		} else {
			if(ip_header->protocol == 17) {
				printk(KERN_INFO "start saw a udp packet %u\n", udp_skb);
				udp_skb = skb_clone (skb, GFP_ATOMIC);
				printk(KERN_INFO "saw a udp packet %u\n", udp_skb);
				times ++;
				return NF_ACCEPT;
			}
			else {
				return NF_ACCEPT;
			}
		}
	}
}





int send_udp_packet(void) {

	int size, err;
	int bufsize = 10;
	unsigned char buf[bufsize+1];
	struct timeval s_time,e_time;

	struct socket *sock_send;
	struct sockaddr_in addr_send;
	//printk(KERN_INFO MODULE_NAME": Could not %u %u \n",&sock_send, sock_send);
	/* create a socket */
	if ( (err = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock_send)) < 0 )
	{
			printk(KERN_INFO MODULE_NAME": Could not create a datagram socket, error = %d\n", -ENXIO);
			return 1;
	}


	memset(&addr_send, 0, sizeof(struct sockaddr));
	addr_send.sin_family = AF_INET;
	addr_send.sin_addr.s_addr = htonl(INADDR_SEND);
	addr_send.sin_port = htons(CONNECT_PORT);

	if  (err = sock_send->ops->connect(sock_send, (struct sockaddr *)&addr_send, sizeof(struct sockaddr), 0) < 0 )
	{
			printk(KERN_INFO MODULE_NAME": Could not bind or connect to socket, error = %d\n", -err);
			return 1;
	}

	//printk(KERN_INFO MODULE_NAME": sending to port %d IP %x\n", CONNECT_PORT, INADDR_SEND);


	 memset(&buf, 0, bufsize+1);
	 strcat(buf, "testing...");
	// do_gettimeofday(&s_time);

	  ksocket_send(sock_send, &addr_send, buf, strlen(buf));
		
	//do_gettimeofday(&e_time);

	//printk(KERN_INFO MODULE_NAME": Time taken %ld \n",timeval_diff(NULL,&e_time,&s_time));

	sock_release(sock_send);
	//kthread->sock_send = NULL;
	// kfree(kthread);
	return 1;
}
        
int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len)
{
        struct msghdr msg;
        struct iovec iov;
        mm_segment_t oldfs;
        int size = 0;

        if (sock->sk==NULL)
           return 0;

        iov.iov_base = buf;
        iov.iov_len = len;

        msg.msg_flags = 0;
        msg.msg_name = addr;
        msg.msg_namelen  = sizeof(struct sockaddr_in);
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;

        oldfs = get_fs();
        set_fs(KERNEL_DS);
        size = sock_sendmsg(sock,&msg,len);
        set_fs(oldfs);

        return size;
}

int setup_skb_packet(struct sk_buff *skb, char * data, int len) {
	//char *data="t";
	printk("In send skb : skb is %u\n",skb);
	
	//struct sk_buff * u_skb;
	
	struct net_device * eth4 = dev_get_by_name(&init_net, "eth4" ) ;
	struct net_device * eth5 = dev_get_by_name(&init_net, "eth5" ) ;
	struct net_device * o_dev;
	
	//u_skb = alloc_skb(1200, GFP_ATOMIC);
	//skb_put(u_skb,1200);
	//memcpy(u_skb->data,skb->data, 28);
	//u_skb->pkt_type = PACKET_OUTGOING; 
	
	printk("pkt type :%d %s\n", skb->pkt_type, skb->dev->name);
	skb->pkt_type = PACKET_OUTGOING; 
	printk("pkt type :%d \n", skb->pkt_type);
	
	if (eth4 == skb->dev)
	{
		skb->dev = eth5;
		o_dev=eth5;
	} else if (eth5 == skb->dev)
	{
		skb->dev = eth4;
		o_dev=eth4;
	} else {
		skb->dev = eth4;
		o_dev=eth4;
	}
	//u_skb->dev=skb->dev;
	ip_header = (struct iphdr *)skb_network_header(skb);
	//ip_header->protocol=18;
	ip_header->tot_len=htons(len+28);
	
	udp_header = (struct udphdr *)((char *)(skb->data) + 20);
	printk("UDP Len is %d\n",ntohs(udp_header->len));
	udp_header->len=htons(len+8);
	
//	*((skb->data)+28)='K';
	skb_trim(skb,len+28);
	copy_from_user(((skb->data)+28),data,len);
	//printk("Hard xmit %d \n",o_dev->hard_start_xmit(skb,o_dev));

	
	return 1;
/*	struct net_device * eth0 = dev_get_by_name(&init_net, "eth0" ) ;
	struct sk_buff *skb;
	
	skb->dev = eth0; 
	skb->pkt_type = PACKET_OUTGOING; 
	dev_queue_xmit(skb); 
	
	
	
	    struct sk_buff *new_skb = skb_copy(skb, GFP_ATOMIC);
         struct ethhdr *eth_data;
           uint8_t *hwaddr;
           if( new_skb != NULL ) {
                   new_skb->dev = tx_dev;
                        new_skb->priority = 1;

                    new_skb->mac.raw = (unsigned char *)new_skb->data;
                    eth_data = eth_hdr(new_skb);
                    hwaddr = tx_dev->perm_addr;

                        memcpy(eth_data->h_source, hwaddr, ETH_ALEN);
                        dev_queue_xmit(new_skb);
                } else
                        DEBUG_PRINTK("unable to copy skb\n");
	*/
	
	
	return 1;
}




int init_module(void)
{
	
	
	
		int ret_val;
	/* 
	 * Register the character device (atleast try) 
	 */
	ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &Fops);

	/* 
	 * Negative values signify an error 
	 */
	if (ret_val < 0) {
		printk(KERN_ALERT "%s failed with %d\n",
		       "Sorry, registering the character device ", ret_val);
		return ret_val;
	}

	printk(KERN_INFO "%s The major device number is %d.\n",
	       "Registeration is a success", MAJOR_NUM);
	printk(KERN_INFO "If you want to talk to the device driver,\n");
	printk(KERN_INFO "you'll have to create a device file. \n");
	printk(KERN_INFO "We suggest you use:\n");
	printk(KERN_INFO "mknod %s c %d 0\n", DEVICE_FILE_NAME, MAJOR_NUM);
	printk(KERN_INFO "The device file name is important, because\n");
	printk(KERN_INFO "the ioctl program assumes that's the\n");
	printk(KERN_INFO "file you'll use.\n");
	
	
	
	int i=0;
	//struct timeval s_time,e_time;
    printk(KERN_INFO "init_module() called\n");
    //   printk(KERN_INFO "calling arp send\n");
    // send_arp_request();

   
	nfho.hook     = hook_func;
   	nfho.hooknum  = 1;
	nfho.pf       = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);

	printk("Called hook fn\n");
	
	printk(KERN_INFO " calling udp\n");
	send_udp_packet();

	
    return 0;
    
    
}

void cleanup_module(void)
{
	
		int ret;

	/* 
	 * Unregister the device 
	 */
	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);

	/* 
	 * If there's an error, report it 
	 */
	if (ret < 0)
		printk(KERN_ALERT "Error: unregister_chrdev: %d\n", ret);
		
		
	struct timeval s_time,e_time;
	printk(KERN_INFO"Unloading the module. times is %d..\n", times);
/*	
	if(times>0) {
		printk(KERN_INFO " calling skb send\n");
		do_gettimeofday(&s_time);
		send_skb_packet(udp_skb);
		do_gettimeofday(&e_time);
		printk(KERN_INFO MODULE_NAME": Time taken %ld \n",timeval_diff(NULL,&e_time,&s_time));

	}
	*/
	kfree_skb(udp_skb);
	nf_unregister_hook(&nfho);
	
    printk(KERN_INFO "cleanup_module() called\n");
}


