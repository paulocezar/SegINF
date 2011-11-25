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
	int src_port, dst_port, rule_id;
	__u8 protocol;
	struct rule__ *next;
	char src[16];
	char dst[16];
} rule;

char src__[16], dst__[16];

static rule *head = NULL;
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
		
	rule *cur;
	int sport = -1, dport = -1;
	__u8 proto;
	
	if( !skb ) return NF_ACCEPT;
	
	ip_hdr__ = (struct iphdr *)skb_network_header(skb);
	
	proto = ip_hdr__->protocol;
	sprintf( src__, "%pI4", &(ip_hdr__->saddr) );
	sprintf( dst__, "%pI4", &(ip_hdr__->daddr) );
	
	if( proto == IPPROTO_TCP ){
		if( skb_network_header(skb) == skb_transport_header(skb) ) 
			tcp_hdr__ = (struct tcphdr*)(skb_transport_header(skb)+ip_hdrlen(skb));
		else
			tcp_hdr__ = (struct tcphdr*)(skb_transport_header(skb));

		sport = (int)ntohs(tcp_hdr__->source);
		dport = (int)ntohs(tcp_hdr__->dest);
	} else if( proto == IPPROTO_UDP ){
		if( skb_network_header(skb) == skb_transport_header(skb) )
			udp_hdr__ = (struct udphdr*)(skb_transport_header(skb)+ip_hdrlen(skb));
		else
			udp_hdr__ = (struct udphdr*)(skb_transport_header(skb));
			
		sport = (int)ntohs(udp_hdr__->source);
		dport = (int)ntohs(udp_hdr__->dest);
	}
	
	printk( KERN_INFO "filtering..\n\t%s:%d\n", src__, sport );
	printk( KERN_INFO "\t%s:%d\n", dst__, dport );
	if( sport == -1 || dport == -1 ) printk( KERN_INFO "%d\n", (int)proto );	

	cur = head;
	while( cur != NULL ){
		if( cur->action != default_policy ){
			
			if( strcmp(src__,cur->src) && (*(cur->src)) ) goto next_one__;
			if( strcmp(dst__,cur->dst) && (*(cur->dst)) ) goto next_one__;
			if( (proto != cur->protocol) && (cur->protocol != -1) ) goto next_one__;
			if( (dport != cur->dst_port) && (cur->dst_port != -1) ) goto next_one__;
			if( (sport != cur->src_port) && (cur->src_port != -1) ) goto next_one__;
			
			return cur->action;
		}
next_one__:
		cur = cur->next;
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
 
	if( buffer[0] == 'd' ){
		if( buffer[8] == 'd' ) default_policy = NF_DROP;
		else default_policy = NF_ACCEPT;
	} else if( buffer[0] == 'r' ){
		
		int wntd = 0;
		int pos = 7;
		rule *nxt, *aux = head;
		
		while( buffer[pos] != ' ' ){
			wntd = 10*wntd + (buffer[pos]-'0');
			pos++;
		}
		
		while( true ){	
			
			if( wntd == head->rule_id ){
				head = head->next;
				printk(KERN_INFO "removendo: %u %s:%d %s:%d %u\n", aux->action, aux->src,
										aux->src_port, aux->dst, aux->dst_port, aux->protocol );
				kfree( aux );
				break;
			}

			if( wntd == 1 ){
				nxt = NULL;
				while( 1 != aux->rule_id ){
					nxt = aux;
					aux->rule_id = aux->rule_id - 1;
					aux = aux->next;
				}
				if( nxt != NULL ) nxt->next = NULL;
				printk(KERN_INFO "removendo: %u %s:%d %s:%d %u\n", aux->action, aux->src,
										aux->src_port, aux->dst, aux->dst_port, aux->protocol );
				kfree( aux );
				break;
			}

			aux->rule_id = aux->rule_id - 1;
			if( aux->rule_id == wntd ){
				nxt = aux->next;
				if( nxt != NULL ){
					aux->next = nxt->next;
					printk(KERN_INFO "removendo: %u %s:%d %s:%d %u\n", nxt->action, nxt->src,
										nxt->src_port, nxt->dst, nxt->dst_port, nxt->protocol );
					kfree( nxt );
				} else kfree( aux );
				break;
			}
			aux = aux->next;
		}
		
	} else {
		int pos, j, beg, sz;		
		rule *newrule = (rule*) kmalloc( sizeof(rule), GFP_KERNEL );
		
		if( newrule == NULL ){
			printk(KERN_INFO "SegINF: cannot allow space for data..\n");
			return -ENOSPC;
		}		
		
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
					
					if( !strncmp(buffer+beg, "IPPROTO_ICMP", sz ) )
						newrule->protocol = IPPROTO_ICMP;
					else if( !strncmp(buffer+beg, "IPPROTO_IGMP", sz ) )
						newrule->protocol = IPPROTO_IGMP;
					else if( !strncmp(buffer+beg, "IPPROTO_IPIP", sz ) )
						newrule->protocol = IPPROTO_IPIP;
					else if( !strncmp(buffer+beg, "IPPROTO_TCP", sz ) )
						newrule->protocol = IPPROTO_TCP;
					else if( !strncmp(buffer+beg, "IPPROTO_EGP", sz ) )
						newrule->protocol = IPPROTO_EGP;
					else if( !strncmp(buffer+beg, "IPPROTO_PUP", sz ) )
						newrule->protocol = IPPROTO_PUP;
					else if( !strncmp(buffer+beg, "IPPROTO_UDP", sz ) )
						newrule->protocol = IPPROTO_UDP;
					else if( !strncmp(buffer+beg, "IPPROTO_IDP", sz ) )
						newrule->protocol = IPPROTO_IDP;
					else if( !strncmp(buffer+beg, "IPPROTO_DCCP", sz ) )
						newrule->protocol = IPPROTO_DCCP;
					else if( !strncmp(buffer+beg, "IPPROTO_RSVP", sz ) )
						newrule->protocol = IPPROTO_RSVP;
					else if( !strncmp(buffer+beg, "IPPROTO_GRE", sz ) )
						newrule->protocol = IPPROTO_GRE;
					else if( !strncmp(buffer+beg, "IPPROTO_IPV6", sz ) )
						newrule->protocol = IPPROTO_IPV6;
					else if( !strncmp(buffer+beg, "IPPROTO_ESP", sz ) )
						newrule->protocol = IPPROTO_ESP;
					else if( !strncmp(buffer+beg, "IPPROTO_AH", sz ) )
						newrule->protocol = IPPROTO_AH;
					else if( !strncmp(buffer+beg, "IPPROTO_BEETPH", sz ) )
						newrule->protocol = IPPROTO_BEETPH;
					else if( !strncmp(buffer+beg, "IPPROTO_PIM", sz ) )
						newrule->protocol = IPPROTO_PIM;
					else if( !strncmp(buffer+beg, "IPPROTO_COMP", sz ) )
						newrule->protocol = IPPROTO_COMP;
					else if( !strncmp(buffer+beg, "IPPROTO_SCTP", sz ) )
						newrule->protocol = IPPROTO_SCTP;
					else if( !strncmp(buffer+beg, "IPPROTO_UDPLITE", sz ) )
						newrule->protocol = IPPROTO_UDPLITE;
					else if( !strncmp(buffer+beg, "IPPROTO_RAW", sz ) )
						newrule->protocol = IPPROTO_RAW;
					
					break;
			}
		}

		printk( KERN_INFO "adicionou regra: \n");
		printk( KERN_INFO "SRC: %s\n", newrule->src );
		printk( KERN_INFO "DST: %s\n", newrule->dst );
		printk( KERN_INFO "SRC PRT: %d\n", newrule->src_port );
		printk( KERN_INFO "DST PRT: %d\n", newrule->dst_port );
		printk( KERN_INFO "PROTOCOL: %d\n", newrule->protocol );
		printk( KERN_INFO "ACTIOn: %u\n", newrule->action );	

		newrule->next = head;
		head = newrule;
		if( newrule->next == NULL ) newrule->rule_id = 1;
		else newrule->rule_id = newrule->next->rule_id+1;
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
	rule *nxt;
	while( head != NULL ){
		nxt = head->next;
		kfree( head );
		head = nxt;
	}

	nf_unregister_hook(&seginf_rules_in);
	nf_unregister_hook(&seginf_rules_out);

	if( seginf_firewall )
		remove_proc_entry(seginf_procfs, NULL);
		
	printk(KERN_INFO "SegINF Firewall Disabled.. you are unprotected now!\n");
}
 
MODULE_LICENSE("Beerware");
MODULE_AUTHOR("Paulo Cezar P. Costa");
MODULE_DESCRIPTION("SegINF Firewall Module");
