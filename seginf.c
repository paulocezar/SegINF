#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <net/ip.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>

#include <linux/proc_fs.h>  
#include <asm/uaccess.h>	

#define seginf_procfs "seginf"

typedef struct rule__ {
	unsigned int action;
	int src_port, dst_port, protocol;
	char src[16];
	char dst[16];
} rule;

typedef struct rule_node__ {
	rule* rule;
	struct rule_node__* next;
} rule_node;


char src__[16], dst__[16];
static rule_node *head = NULL;
struct iphdr *ip_hdr__;
struct tcphdr *tcp_hdr__;
struct udphdr *udp_hdr__;


struct nf_hook_ops seginf_rules_in;
struct nf_hook_ops seginf_rules_out;    

static struct proc_dir_entry *seginf_firewall;
static unsigned int default_policy = NF_DROP;
 
unsigned int seginf_hook(unsigned int hooknum,
						 struct sk_buff *skb,
						 const struct net_device *in,
						 const struct net_device *out,
						 int (*okfn)(struct sk_buff *)
		      			)
{
		
	rule_node *cur_node;
	rule *cur;
	int sport = -1, dport = -1;
	unsigned int proto;
	
	if( !skb ) return NF_ACCEPT;
	
	ip_hdr__ = (struct iphdr *)skb_network_header(skb);
	
	proto = ip_hdr__->protocol;
	sprintf( src__, "%pI4", &(ip_hdr__->saddr) );
	sprintf( dst__, "%pI4", &(ip_hdr__->daddr) );
	
	if( proto == IPPROTO_TCP ){
		tcp_hdr__ = (struct tcphdr*)(skb_transport_header(skb)+ip_hdrlen(skb));
		sport = ntohs(tcp_hdr__->source);
		dport = ntohs(tcp_hdr__->dest);
	} else if( proto == IPPROTO_UDP ){
		udp_hdr__ = (struct udphdr*)(skb_transport_header(skb)+ip_hdrlen(skb));
		sport = ntohs(udp_hdr__->source);
		dport = ntohs(udp_hdr__->dest);
	}
	
	//printk( KERN_INFO "filtering..\n\t%s:%d\n", src__, sport );
	//printk( KERN_INFO "\t%s:%d\n", dst__, dport );
	
	cur_node = head;
	while( cur_node != NULL ){
		cur = cur_node->rule;
		if( cur->action != default_policy ){
			
			if( strcmp(src__,cur->src) && (*(cur->src)) ) goto next_one__;
			//printk(KERN_INFO "PASSOU PELO SRC IP\n");
			if( strcmp(dst__,cur->dst) && (*(cur->dst)) ) goto next_one__;
			//printk(KERN_INFO "PASSOU PELO DST IP\n");
			if( (proto != cur->protocol) && (cur->protocol != -1) ) goto next_one__;
			//printk(KERN_INFO "PASSOU PELO PROTOCOL\n");
			if( (dport != cur->dst_port) && (cur->dst_port != -1) ) goto next_one__;
			//printk(KERN_INFO "PASSOU PELO DST PORT\n");
			if( (sport != cur->src_port) && (cur->src_port != -1) ) goto next_one__;
			//printk(KERN_INFO "PASSOU PELO SRC PORT\n");
			
			return cur->action;
		}
next_one__:
		cur_node = cur_node->next;
	}
	
	return default_policy;
}
 
int seginf_write(struct file *file, const char *buffer,
				unsigned long len, void *data)
{
	
	if(len > PAGE_SIZE || len < 0){
		printk(KERN_INFO "SegINF: cannot allow space for data..\n");
		return -ENOSPC;
	}
 
	/*if(copy_from_user(&userData, buffer, len)){
		printk(KERN_INFO "SegINF: cannot copy data from userspace..\n");
		return -EFAULT;
	}*/
	if( buffer[0] == 'd' ){
		if( buffer[8] == 'd' ) default_policy = NF_DROP;
		else default_policy = NF_ACCEPT;
	} else {
				
		rule *newrule = (rule*) kmalloc( sizeof(rule), GFP_USER );	
		rule_node *new_rule_node;
		int pos, j, beg, sz;
		
		if( buffer[0] == 'b' ) newrule->action = NF_DROP;
		else newrule->action = NF_ACCEPT;
	
		newrule->src[0] = '\0';
		newrule->dst[0] = '\0';
		newrule->src_port = -1;
		newrule->dst_port = -1;
		newrule->protocol = -1;
	
		pos = 5;
		while( pos+1 < len ){
			pos+=2;
		
			switch( buffer[pos] ){
				case 'i': 
					pos+=2;
					j = 0;
					while( buffer[pos] != ' ' ){
						newrule->src[j] = buffer[pos];
						j++; pos++;
					}
					newrule->src[j] = '\0';
					break;
				case 'o':
					pos+=2;
					j = 0;
					while( buffer[pos] != ' ' ){ newrule->dst[j] = buffer[pos]; j++; pos++; }
					newrule->dst[j] = '\0';
					break;
				case 's':
					pos+=2;
					newrule->src_port = 0;
					while( buffer[pos] != ' ' ){ 
						newrule->src_port = (newrule->src_port)*10 + (buffer[pos]-'0');
						pos++;
					}
					break;
				case 'd':
					pos+=2;
					newrule->dst_port = 0;
					while( buffer[pos] != ' ' ){ 
						newrule->dst_port = (newrule->dst_port)*10 + (buffer[pos]-'0');
						pos++;
					}
					break;
				case 'p':
					pos+=2;
					beg = pos;
					while( buffer[pos] != ' ' ) pos++;
					sz = pos-beg;
					
					if( !strncmp(buffer+beg, "IPPROTO_TCP", sz ) )
						newrule->protocol = IPPROTO_TCP;
					else if( !strncmp(buffer+beg, "IPPROTO_UDP", sz ) )
						newrule->protocol = IPPROTO_UDP;
					else if( !strncmp(buffer+beg, "IPPROTO_ICMP", sz ) )
						newrule->protocol = IPPROTO_ICMP;
						
					break;
			}
		}

/*		printk( KERN_INFO "adicionou regra: \n");
		printk( KERN_INFO "SRC: %s\n", newrule->src );
		printk( KERN_INFO "DST: %s\n", newrule->dst );
		printk( KERN_INFO "SRC PRT: %d\n", newrule->src_port );
		printk( KERN_INFO "DST PRT: %d\n", newrule->dst_port );
		printk( KERN_INFO "PROTOCOL: %d\n", newrule->protocol );
		printk( KERN_INFO "ACTIOn: %u\n", newrule->action );
*/	

		new_rule_node = (rule_node*)kmalloc(sizeof(rule_node), GFP_USER);
		new_rule_node->rule = newrule;
		new_rule_node->next = head;
		head = new_rule_node;
	}
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
	} else {
		seginf_firewall->write_proc = seginf_write;
    
		seginf_rules_in.hook = seginf_hook;
		seginf_rules_in.hooknum = NF_INET_PRE_ROUTING;
		seginf_rules_in.pf = PF_INET;
		seginf_rules_in.priority = NF_IP_PRI_LAST;

		seginf_rules_out.hook = seginf_hook;
		seginf_rules_out.hooknum = NF_INET_POST_ROUTING;
		seginf_rules_out.pf = PF_INET;
		seginf_rules_out.priority = NF_IP_PRI_LAST;
		
		nf_register_hook(&seginf_rules_in);
		nf_register_hook(&seginf_rules_out);
		head = NULL;
		
		printk(KERN_INFO "SegINF Firewall Module is up! May the be force with you!\n");
	}
    return ret;
}

void cleanup_module()
{
	nf_unregister_hook(&seginf_rules_in);
	nf_unregister_hook(&seginf_rules_out);

	if( seginf_firewall )
		remove_proc_entry(seginf_procfs, NULL);
		
	printk(KERN_INFO "SegINF Firewall Disabled.. you are unprotected now!\n");
}
 
MODULE_LICENSE("Beerware");
MODULE_AUTHOR("Paulo Cezar P. Costa");
MODULE_DESCRIPTION("SegINF Firewall Module");
