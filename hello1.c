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

#define DEFAULT_PORT 2325
#define CONNECT_PORT 16767
#define MODULE_NAME "ksocket"
//#define INADDR_SEND ((unsigned long int)0x7f000001) /* 127.0.0.1 */
#define INADDR_SEND ((unsigned long int)0x980E5C01) /* 127.0.0.1 */
//#define INADDR_SEND INADDR_LOOPBACK



/* function prototypes */
int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len);






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

int send_udp_packet_old(void)  {
mm_segment_t oldfs; 
int size = 0; 
int error = 0; 
char *warp_dev="eth0"; 
char dev[20]; 
char*buf="This is a message from kernel";
struct iovec iov; 
struct sockaddr sa; 
struct msghdr msg; 

struct socket *sock; 
//int source_port=16767;

if ((error=sock_create(PF_INET, SOCK_DGRAM, 0, &sock))<0) { 
printk(KERN_WARNING "Could not create a PF_PACKET SOCK_RAW Socket\n"); 
return (-1); 
} 

memset(&sa,0,sizeof(sa)); 
strcpy(dev,warp_dev); 
strncpy(sa.sa_data,dev,sizeof(sa.sa_data)); 

error = sock->ops->bind(sock,&sa,sizeof(sa)); 
if (error<0) 
{ 
printk(KERN_WARNING "Error binding socket"); 
return -1; 
} 
 //the bind operations
 
    /*   addr_in->sin_family=PF_INET;
       addr_in->sin_port = htons(source_port);
       addr_in->sin_addr.s_addr = source_address;
       memset(&(addr_in->sin_zero), '\0', 8);
 
       knetlog->addr_in = addr_in;
       retval = sock->ops->bind(sock, (struct sockaddr *) knetlog->addr_in,
		sizeof(struct sockaddr));*/
 
//to enable broadcast:
   /*    lock_sock(sock->sk);
       sock->sk->broadcast = 1;
       release_sock(sock->sk);
 */
iov.iov_base = (char *)buf; 
iov.iov_len = (__kernel_size_t) strlen(buf); 

msg.msg_iov = &iov; 
msg.msg_iovlen = 1; 
msg.msg_control = NULL; 
msg.msg_controllen = 0; 
msg.msg_name = NULL; 
msg.msg_namelen = 0; 
msg.msg_flags = 0; 

 
// now, your UDP packet could be sent by:
       oldfs = get_fs(); 
       set_fs(KERNEL_DS);   /* Required to change addr_limit */
       error = sock_sendmsg(sock, &msg, iov.iov_len);
       set_fs(oldfs);

if (error < 0) 
printk(KERN_WARNING "sock_sendmsg error: %d\n",size); 

return 0;
}


int send_udp_packet_2nd(void)
{
	u32 destination;
	u16 port = 16767;
	u16 id =12122;
	__be16 outbuf = htons(id);
	struct socket *sock;
	struct sockaddr sa; 
	struct msghdr msg;
	char dev[20]; 
        struct iovec iov;
	struct sockaddr_in whereto;
	char *warp_dev="eth0"; 
	int size;	
	char *address="152.14.92.55";
	char *buf="This is a message from kernel";
//	int len = 20;
	int len = sizeof(u16);
	int ret;
	destination = ((unsigned long int)0x7f000001);
	printk("destination: %u\n", destination);


memset(&sa,0,sizeof(sa)); 
strcpy(dev,warp_dev); 
strncpy(sa.sa_data,dev,sizeof(sa.sa_data)); 
	
	ret=sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
	
	
        if(ret < 0) {
	printk("socket create error :\n");
	 return -1;			
	}
	
	/* fillout sockaddr_in-structure whereto */

	port = htons(port);

	memset(&whereto, 0, sizeof(whereto));
	whereto.sin_family = AF_INET;
	whereto.sin_addr.s_addr = htonl(destination);
	whereto.sin_port =htons(port);

//ret = sock->ops->bind(sock,&sa,sizeof(sa)); 
/*if (ret<0) 
{ 
printk(KERN_WARNING "Error binding socket %d" , ret); 
return -1; 
} */

	/* "connect" */
	if( (sock->ops->connect(sock, (struct sockaddr *)&whereto,
				sizeof(struct sockaddr), 0) )< 0)
		return -1;
	printk("connected:\n");
        iov.iov_base = buf;
        iov.iov_len = len;
	
        msg.msg_flags = 0;
        msg.msg_name = &whereto;
        msg.msg_namelen  = sizeof(struct sockaddr_in);
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;

	
        /* fire! */
	len = iov.iov_len;

		size = sock_sendmsg(sock, &msg, len);
		printk("sock_sendmsg : %d\n", size);		
		if (size < 0){
			printk("sock_sendmsg error: %d\n", size);			
		}

	
	sock_release(sock);
	

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

int send_skb_packet(void) {
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
	int i=0;
	//struct timeval s_time,e_time;
    printk(KERN_INFO "init_module() called\n");
    //   printk(KERN_INFO "calling arp send\n");
    // send_arp_request();

    printk(KERN_INFO " calling udp\n");
	send_udp_packet();
    return 0;
    
    printk(KERN_INFO " calling skb send\n");
	send_skb_packet();
    return 0;
    
    
}

void cleanup_module(void)
{
        printk(KERN_INFO "cleanup_module() called\n");
}


