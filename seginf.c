#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/proc_fs.h>  
#include <asm/uaccess.h>	
 
struct nf_hook_ops seginf_rules;   
 
#define seginf_procfs "seginf"
 
static struct proc_dir_entry *seginf_firewall;

static int can_accept = 0;
 
unsigned int seginf_hook(unsigned int hooknum,
						 struct sk_buff *skb,
						 const struct net_device *in,
						 const struct net_device *out,
						 int (*okfn)(struct sk_buff *)
		      			)
{
	return can_accept ? NF_ACCEPT : NF_DROP;
}

int seginf_read(char *page, char **start, off_t off,
	     int count, int *eof, void *data)
{
	int len;

	if(off > 0){
		*eof = 1;
		return 0;
	}

	if(count < sizeof(int)){
		*eof = 1;
		return -ENOSPC;
	}

	memcpy(page, &can_accept, sizeof(int));
	len = sizeof(int);

	return len;
}
 
int seginf_write(struct file *file, const char *buffer,
				unsigned long len, void *data)
{
	unsigned char userData;

	if(len > PAGE_SIZE || len < 0){
		printk(KERN_INFO "SegINF: cannot allow space for data..\n");
		return -ENOSPC;
	}
 
	if(copy_from_user(&userData, buffer, 1)){
		printk(KERN_INFO "SegINF: cannot copy data from userspace..\n");
		return -EFAULT;
	}

	can_accept = simple_strtol(&userData, NULL, 10);
	return len;
}
 
int init_module()
{
	struct proc_dir_entry proc_root;
	int ret = 0;

	seginf_firewall = create_proc_entry( seginf_procfs, 0644, NULL );

	if(seginf_firewall == NULL){
		ret = -ENOMEM;
		if( seginf_firewall )
			remove_proc_entry( seginf_procfs, &proc_root);

		printk(KERN_INFO "SegINF: cannot allocate memory..\n");
		goto hell;
	} else {
		seginf_firewall->read_proc = seginf_read;
		seginf_firewall->write_proc = seginf_write;
    }
	seginf_rules.hook = seginf_hook;
    seginf_rules.hooknum = NF_INET_PRE_ROUTING;
    seginf_rules.pf = PF_INET;
    seginf_rules.priority = NF_IP_PRI_LAST;

    nf_register_hook(&seginf_rules);

	printk(KERN_INFO "SegINF Firewall Module is up! May the be force with you!\n");

hell:
    return ret;
}
 
void cleanup_module()
{
	nf_unregister_hook(&seginf_rules);

	if ( seginf_firewall )
		remove_proc_entry(seginf_procfs, NULL);

	printk(KERN_INFO "SegINF Firewall Disabled.. you are unprotected now!\n");
}
 
MODULE_LICENSE("Beerware");
MODULE_AUTHOR("Paulo Cezar P. Costa");
MODULE_DESCRIPTION("SegINF Firewall Module");
