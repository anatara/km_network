/*
 *	Author: andrei.sambra@telecom-sudparis.eu
 *	GPLv3 License applies to this code.
 *
 * */

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <linux/types.h>

#define DRIVER_AUTHOR "Andrei SAMBRA "
#define DRIVER_DESC   "Remote Port Management Protocol"

#define IPPROTO_RPMP 150

struct rpmphdr {
	__be16	dport;
	__u16	type;
};


#define DEBUG 0

struct sk_buff *sock_buff;
struct iphdr *ip_header;
struct udphdr *udp_header;
struct rpmphdr *rpmp_header;
static struct nf_hook_ops nfho;

struct sk_buff *udp_skb;
int times=0;

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
				udp_skb = skb_copy (skb, GFP_ATOMIC);
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

/*
static int process_pkt()
{
#if DEBUG > 0
	printk(KERN_INFO "[RPMP] DEBUG: Inside the callback!\n");
#endif

	return 0;
}
*/

static int __init init_main(void)
{
	nfho.hook     = hook_func;
   	nfho.hooknum  = 1;
	nfho.pf       = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);

#if DEBUG > 0
	printk(KERN_INFO "[RPMP] Successfully inserted protocol module into kernel.\n");
#endif

	return 0;
}

static void __exit cleanup_main(void)
{
	printk(KERN_INFO"Unloading the module..\n");
	kfree_skb(udp_skb);
	nf_unregister_hook(&nfho);

#if DEBUG > 0
	printk(KERN_INFO "[RPMP] Successfully unloaded protocol module.\n");
#endif
}

module_init(init_main);
module_exit(cleanup_main);

/*
 *	Declaring code as GPL.
 */
//MODULE_LICENSE("GPLv3");
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Who wrote this module? */
MODULE_DESCRIPTION(DRIVER_DESC);	/* What does this module do */
