/*
 * Transparent proxy support for Linux/iptables
 *
 * Copyright (c) 2002-2004 BalaBit IT Ltd.
 * Author: Balázs Scheidler, Krisztián Kovács
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/version.h>
#include <linux/module.h>

#include <linux/sysctl.h>
#include <linux/vmalloc.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/if.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/time.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/sock.h>
#include <asm/uaccess.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_TPROXY.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_core.h>
#include <linux/netfilter_ipv4/ip_nat.h>
#include <linux/netfilter_ipv4/ip_nat_core.h>

#include <linux/netfilter_ipv4/ip_tproxy.h>

#define ASSERT_READ_LOCK(x) MUST_BE_READ_LOCKED(&ip_tproxy_lock)
#define ASSERT_WRITE_LOCK(x) MUST_BE_WRITE_LOCKED(&ip_tproxy_lock)
DECLARE_RWLOCK(ip_tproxy_lock);

#include <linux/netfilter_ipv4/listhelp.h>

#define TPROXY_VALID_HOOKS ((1 << NF_IP_PRE_ROUTING) | (1 << NF_IP_LOCAL_OUT))

#if 0
#define DEBUGP printk
#define IP_TPROXY_DEBUG
#else
#define DEBUGP(f, args...)
#endif

#define TPROXY_MAJOR_VERSION 2
#define TPROXY_MINOR_VERSION 0
#define TPROXY_PATCH_VERSION 6

#define TPROXY_FULL_VERSION ((TPROXY_MAJOR_VERSION << 24) | \
			     (TPROXY_MINOR_VERSION << 16) | \
			     TPROXY_PATCH_VERSION)

#define MAJOR_VERSION(x) ((x >> 24) & 0xff)
#define MINOR_VERSION(x) ((x >> 16) & 0xff)
#define PATCH_VERSION(x) (x & 0xffff)

/* simple and buggy, but enough for us */
#define MIN(a,b) ((a < b) ? a : b)

/* Standard entry. */
struct ipt_standard
{
	struct ipt_entry entry;
	struct ipt_standard_target target;
};

struct ipt_error_target
{
	struct ipt_entry_target target;
	char errorname[IPT_FUNCTION_MAXNAMELEN];
};

struct ipt_error
{
	struct ipt_entry entry;
	struct ipt_error_target target;
};

static struct
{
	struct ipt_replace repl;
	struct ipt_standard entries[2];
	struct ipt_error term;
} initial_table __initdata
= { { "tproxy", TPROXY_VALID_HOOKS, 3,
      sizeof(struct ipt_standard) * 2 + sizeof(struct ipt_error),
      { [NF_IP_PRE_ROUTING] 0,
	[NF_IP_LOCAL_OUT] sizeof(struct ipt_standard) },
      { [NF_IP_PRE_ROUTING] 0,
	[NF_IP_LOCAL_OUT] sizeof(struct ipt_standard) },
      0, NULL, { } },
    {
	    /* PRE_ROUTING */
	    { { { { 0 }, { 0 }, { 0 }, { 0 }, "", "", { 0 }, { 0 }, 0, 0, 0 },
		0,
		sizeof(struct ipt_entry),
		sizeof(struct ipt_standard),
		0, { 0, 0 }, { } },
	      { { { { IPT_ALIGN(sizeof(struct ipt_standard_target)), "" } }, { } },
		-NF_ACCEPT - 1 } },
	    /* LOCAL_OUT */
	    { { { { 0 }, { 0 }, { 0 }, { 0 }, "", "", { 0 }, { 0 }, 0, 0, 0 },
		0,
		sizeof(struct ipt_entry),
		sizeof(struct ipt_standard),
		0, { 0, 0 }, { } },
	      { { { { IPT_ALIGN(sizeof(struct ipt_standard_target)), "" } }, { } },
		-NF_ACCEPT - 1 } }
    },
    /* ERROR */
    { { { { 0 }, { 0 }, { 0 }, { 0 }, "", "", { 0 }, { 0 }, 0, 0, 0 },
	0,
	sizeof(struct ipt_entry),
	sizeof(struct ipt_error),
	0, { 0, 0 }, { } },
      { { { { IPT_ALIGN(sizeof(struct ipt_error_target)), IPT_ERROR_TARGET } },
	  { } },
	"ERROR"
      }
    }
};

static struct ipt_table tproxy_table
= { { NULL, NULL }, "tproxy", &initial_table.repl,
    TPROXY_VALID_HOOKS, RW_LOCK_UNLOCKED, NULL };

static void (*ip_conntrack_destroyed_old)(struct ip_conntrack *ct) = NULL;

/* NAT entry setup flags */
#define TN_BIDIR	1
#define TN_STOREREF	2

/* user settable flags */
#define TF_NAT_ONCE       0x00000001 /* this entry is applied only once */
#define TF_LISTEN         0x00000002 /* this entry is meant for listening */
#define TF_CONNECT        0x00000004 /* this entry is meant for connecting */
#define TF_UNIDIR	  0x00000008 /* this entry is a listening UDP socket, 
					and only an unidirectional nat is to be applied */

/* state flags */
#define TF_HASHED         0x00010000 /* entry hashed in hashtable */
#define TF_CONNECT_ONLY   0x00020000 /* conflicting foreign address */
#define TF_MARK_ONLY      0x00040000 /* have packets in this session mark as tproxy but don't apply translation */
#define TF_NAT_APPLIED    0x00080000 /* NAT already applied, ignore this entry during NAT search */
#define TF_ORPHAN         0x00100000 /* Parent (listening) socket was closed */

#ifdef CONFIG_IP_NF_NAT_NRES
#define TF_NAT_RESERVED   0x00200000 /* a NAT reservation was allocated for the sockref's foreign address */
#define TF_NAT_PEER       0x00400000 /* raddr was also specified at NAT reservation */
#endif

#define TF_STATE_MASK     0xffff0000

struct ip_tproxy_sockref;

struct ip_tproxy_hash
{
	struct list_head list;
	struct ip_tproxy_sockref *sockref;
};

struct ip_tproxy_sockref 
{
	int flags;
	atomic_t references;
	
	u8 proto;

	/* foreign address associated with a local socket */
	u32 faddr;
	u16 fport;
	
	/* local socket address */
	u32 laddr;
	u16 lport;
	
	/* remote addresses, needed for datagram protocols when the peer
	 * sends the packet triggering the NAT translation. (as there might
	 * be multiple sockrefs on the same foreign address).
	 */
	u32 raddr;
	u16 rport;
	
	/* hash chains indexed by local and foreign addresses */
	struct ip_tproxy_hash bylocal, byforeign;

	/* lock protecting access to related list */
	spinlock_t relatedlock;
	/* number of related connections */
	atomic_t related;
	/* list of related connections */
	struct list_head relatedct;

	/* socket which we were assigned to */
	struct sock *assigned_to;

	/* How many sockets use this sockref? Used for mark-only sockrefs,
	 * which can be shared between multiple sockets bound to the same local
	 * address */
	atomic_t socket_count;

	/* when was this entry inserted in hash */
	struct timeval tv_hashed;
};

static int hashsize = 0;
MODULE_PARM(hashsize, "i");

int ip_tproxy_htable_size = 127;
struct list_head *ip_tproxy_bylocal;
struct list_head *ip_tproxy_byforeign;
kmem_cache_t *ip_tproxy_sockref_table;
int ip_tproxy_htable_count = 0;
struct ip_conntrack ip_tproxy_fake_ct;

static u32
ip_tproxy_hash_fn(u32 addr, u16 port, u8 proto)
{
	return ntohl(addr + (port<<8) + proto) % ip_tproxy_htable_size; 
}

/* allocate memory and initialize a sockref structure */
static struct ip_tproxy_sockref *
ip_tproxy_sockref_new(void)
{
	struct ip_tproxy_sockref *sr;
	
	sr = kmem_cache_alloc(ip_tproxy_sockref_table, GFP_ATOMIC);
        if ( !sr )
           return NULL;
	atomic_set(&sr->references, 1);
	sr->bylocal.sockref = sr;
	sr->byforeign.sockref = sr;
	sr->rport = 0;
	sr->raddr = 0;
	atomic_set(&sr->related, 0);
	sr->relatedlock = SPIN_LOCK_UNLOCKED;
	INIT_LIST_HEAD(&sr->relatedct);
	sr->assigned_to = NULL;
	atomic_set(&sr->socket_count, 1);
	return sr;
}

/* increase reference count for a sockref entry */
static inline void
ip_tproxy_sockref_ref(struct ip_tproxy_sockref *sr)
{
	atomic_inc(&sr->references);
}

/* decrease refcount for the entry, and free the structure if needed */
static inline void
ip_tproxy_sockref_unref(struct ip_tproxy_sockref *sr)
{
	if (atomic_dec_and_test(&sr->references)) {
		kmem_cache_free(ip_tproxy_sockref_table, sr);
	}
}

/* put a sockref entry in the hash tables */
static void
ip_tproxy_hash(struct ip_tproxy_sockref *sr)
{
	u32 fhash = ip_tproxy_hash_fn(sr->faddr, sr->fport, sr->proto);
	u32 lhash = ip_tproxy_hash_fn(sr->laddr, sr->lport, sr->proto);
	
	sr->flags |= TF_HASHED;
	sr->tv_hashed = xtime;

	MUST_BE_WRITE_LOCKED(&ip_tproxy_lock);
	DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_hash(): hashing sockref, "
	       "lhash=%d, fhash=%d, %p, %02x, %08x:%04x -> %08x:%04x\n",
	       lhash, fhash, sr, sr->proto, sr->laddr,
	       sr->lport, sr->faddr, sr->fport);

	ip_tproxy_sockref_ref(sr);
	
	list_append(&ip_tproxy_bylocal[lhash], &sr->bylocal);
	list_append(&ip_tproxy_byforeign[fhash], &sr->byforeign);
	ip_tproxy_htable_count++;
}

/* delete sockref from the hash tables */
static void
ip_tproxy_unhash(struct ip_tproxy_sockref *sr)
{
	MUST_BE_WRITE_LOCKED(&ip_tproxy_lock);
	DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_hash(): unhashing sockref, "
	      "%p, %02x, %08x:%04x -> %08x:%04x\n",
	      sr, sr->proto, sr->laddr, sr->lport, sr->faddr, sr->fport);
	
	if (sr->flags & TF_HASHED) {
		list_del(&sr->bylocal.list);
		list_del(&sr->byforeign.list);
		sr->flags &= ~TF_HASHED;
		ip_tproxy_sockref_unref(sr);
		ip_tproxy_htable_count--;
	}
	else {
		printk(KERN_WARNING "IP_TPROXY: unhashing a sockref which was "
		       "not hashed before, %p, flags=%x\n", 
		       sr, sr->flags);
	}
}

/* change the fport of the sockref to the specified value, and modify foreign hash
 * accordingly (used when not specifying an exact foreign port, and NAT allocates a
 * free port number for the sockref) */
static void
ip_tproxy_rehash_fport(struct ip_tproxy_sockref *sr, u16 fport)
{
	u32 fhash = ip_tproxy_hash_fn(sr->faddr, fport, sr->proto);

	MUST_BE_WRITE_LOCKED(&ip_tproxy_lock);
	DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_rehash_fport(): rehashing sockref, "
	       "%p, %02x, %08x:%04x -> %08x:%04x, new fport %04x\n",
	       sr, sr->proto, sr->laddr, sr->lport,
	       sr->faddr, sr->fport, fport);

	if (sr->flags & TF_HASHED) {
		list_del(&sr->byforeign.list);
		sr->fport = fport;
		list_append(&ip_tproxy_byforeign[fhash], &sr->byforeign);
	}
}

/* add a conntrack entry to the related list of the sockref */
static void
ip_tproxy_relatedct_add(struct ip_tproxy_sockref *sr, struct ip_conntrack *ct)
{
#ifdef IP_TPROXY_DEBUG
	struct ip_conntrack *p;
#endif

	if (test_and_set_bit(IPS_TPROXY_RELATED_BIT, &ct->status)) {
		/* this conntrack is already related to another sockref! */
		return;
	}

	spin_lock_bh(&sr->relatedlock);

#ifdef IP_TPROXY_DEBUG
	/* check if it's already in the list */
	list_for_each_entry(p, &sr->relatedct, tproxy.related) {
		if (ct == p)
			goto out;
	}
#endif

	/* each related conntrack adds one to the reference count of the sockref */
	ip_tproxy_sockref_ref(sr);
	atomic_inc(&sr->related);
	/* since we store a pointer to the conntrack, we should get a reference */
	atomic_inc(&ct->ct_general.use);
	list_add(&ct->tproxy.related, &sr->relatedct);

#ifdef IP_TPROXY_DEBUG
out:
#endif
	spin_unlock_bh(&sr->relatedlock);
}

/* called by conntrack when a connection is confirmed */
static void
ip_tproxy_confirmed(struct ip_conntrack *ct)
{
	struct ip_tproxy_sockref *sr = (struct ip_tproxy_sockref *)ct->tproxy.sockref;

	/* check if it was marked by tproxy and not yet a related sockref */
	if (test_bit(IPS_TPROXY_BIT, &ct->status) &&
	    !test_bit(IPS_TPROXY_RELATED_BIT, &ct->status) &&
	    sr) {
		ct->tproxy.sockref = NULL;

		/* put it on the sockref's related list */
		if (sr->proto == IPPROTO_UDP)
			ip_tproxy_relatedct_add(sr, ct);

		/* drop reference to sockref */
		ip_tproxy_sockref_unref(sr);
	}
}

/* called by conntrack when a connection is destroyed */
static void
ip_tproxy_conntrack_destroyed(struct ip_conntrack *ct)
{
	/* check if it's not confirmed, but marked by tproxy */
	if (!is_confirmed(ct) &&
	    test_bit(IPS_TPROXY_BIT, &ct->status) &&
	    !test_bit(IPS_TPROXY_RELATED_BIT, &ct->status) &&
	    ct->tproxy.sockref != NULL) {
		/* drop reference */
		ip_tproxy_sockref_unref((struct ip_tproxy_sockref *)ct->tproxy.sockref);
		ct->tproxy.sockref = NULL;
		clear_bit(IPS_TPROXY_BIT, &ct->status);
	}

	if (ip_conntrack_destroyed_old)
		ip_conntrack_destroyed_old(ct);
}

static int
sockref_listen_cmp(const struct ip_tproxy_sockref *sr, const u32 raddr, const u16 rport,
		   const struct ip_conntrack *ct)
{
	return (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.ip == sr->faddr) &&
	       (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all == sr->fport) &&
	       (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == sr->proto) &&
	       ((raddr == 0) || (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.ip == raddr)) &&
	       ((rport == 0) || (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all == rport));
}

/* delete matching related connections from the sockref's list and delete them from 
 * the conntrack hash if requested */
static void
ip_tproxy_kill_related(struct ip_tproxy_sockref *sr, u32 raddr, u16 rport,
		       int cmpfn(const struct ip_tproxy_sockref *, const u32 raddr,
			         const u16 rport, const struct ip_conntrack *),
		       int delete)
{
	struct ip_conntrack *ct, *p;

	spin_lock_bh(&sr->relatedlock);
	
	list_for_each_entry_safe(ct, p, &sr->relatedct, tproxy.related) {
		/* if a compare function was given, don't delete unmatched entries */
		if (cmpfn && !cmpfn(sr, raddr, rport, ct))
			continue;

		/* delete the conntrack entry from our related list, update related counter */
		list_del(&ct->tproxy.related);
		atomic_dec(&sr->related);

#ifdef CONFIG_NETFILTER_DEBUG
		/* clear IPS_TPROXY_RELATED flag from the conntrack */
		if (!test_and_clear_bit(IPS_TPROXY_RELATED_BIT, &ct->status)) {
			/* this is a bug: IPS_TPROXY_RELATED is not set for a conntrack? */
			printk(KERN_WARNING "IP_TPROXY: IPS_TPROXY_RELATED not set "
					    "for a related conntrack\n");
		}
#endif

		/* should we delete the entry from the conntrack hash? */
		if (delete && del_timer(&ct->timeout))
			ct->timeout.function((unsigned long)ct);

		/* unreference conntrack and sockref */
		ip_conntrack_put(ct);
		ip_tproxy_sockref_unref(sr);
	}

	spin_unlock_bh(&sr->relatedlock);
}

/* remove/kill related connections for the given sockref */
static void
ip_tproxy_kill_conntracks(struct ip_tproxy_sockref *sr, u32 raddr, u16 rport, int delete)
{
	MUST_BE_WRITE_LOCKED(&ip_tproxy_lock);

	if (sr->flags & TF_CONNECT) {
		/* this is an established UDP "connection" or a CONNECT-ed
		 * sockref, we delete all related connections from our list */
		ip_tproxy_kill_related(sr, raddr, rport, NULL, delete);
	} else if (sr->flags & TF_LISTEN) {
		/* for listening sockrefs, we have to delete one specific
		 * connection only, with both endpoints matching */
		ip_tproxy_kill_related(sr, raddr, rport, sockref_listen_cmp, delete);
	}
}

static void *ip_tproxy_seq_start(struct seq_file *seq, loff_t *pos)
{
	/* we use seq_file->private pointer as an int */
	unsigned int *bucket = (unsigned int *)&seq->private;

	READ_LOCK(&ip_tproxy_lock);

	if (*pos >= ip_tproxy_htable_size)
		return NULL;

	*bucket = *pos;
	return bucket;
}

static void *ip_tproxy_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	unsigned int *bucket = (unsigned int *)v;

	*pos = ++(*bucket);
	if (*pos > ip_tproxy_htable_size)
		return NULL;

	return bucket;
}

static void ip_tproxy_seq_stop(struct seq_file *seq, void *v)
{
	READ_UNLOCK(&ip_tproxy_lock);
}

/* print information about a sockref, used by the procfs interface */
static unsigned int
ip_tproxy_print_sockref(const struct ip_tproxy_hash *h, struct seq_file *seq)
{
	struct ip_tproxy_sockref *sr = h->sockref;

	MUST_BE_READ_LOCKED(&ip_tproxy_lock);

	IP_NF_ASSERT(sr);

	return seq_printf(seq, "%05d %08x:%04x %08x:%04x %08x:%04x %08x %05u %06u %10ld:%06ld\n",
			sr->proto, sr->faddr, sr->fport, sr->laddr,
			sr->lport, sr->raddr, sr->rport, sr->flags,
			atomic_read(&sr->related), atomic_read(&sr->socket_count),
			sr->tv_hashed.tv_sec, sr->tv_hashed.tv_usec) ? 1 : 0;
}

static int ip_tproxy_seq_show(struct seq_file *seq, void *v)
{
	unsigned int *bucket = (unsigned int *)v;

	if (LIST_FIND(&ip_tproxy_bylocal[*bucket], ip_tproxy_print_sockref,
		      struct ip_tproxy_hash *, seq))
		return 1;

	return 0;
}

static struct seq_operations ip_tproxy_seq_ops = {
	.start = ip_tproxy_seq_start,
	.next  = ip_tproxy_seq_next,
	.stop  = ip_tproxy_seq_stop,
	.show  = ip_tproxy_seq_show
};

static int ip_tproxy_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ip_tproxy_seq_ops);
}

static struct file_operations ip_tproxy_file_ops = {
	.owner   = THIS_MODULE,
	.open    = ip_tproxy_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};

/* lookup sockref based on the local address. refcount is not incremented on the returned sockref */
struct ip_tproxy_sockref *
ip_tproxy_sockref_find_local(u32 addr, u16 port, u8 proto, int fresh, u32 raddr, u16 rport)
{
	u32 hash = ip_tproxy_hash_fn(addr, port, proto);
	struct ip_tproxy_hash *h;
	struct ip_tproxy_sockref *sr, *best = NULL;

	ASSERT_READ_LOCK(&ip_tproxy_bylocal[hash]);
	DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_sockref_find_local(): "
	       "entered, %08x:%04x\n", addr, port);

	list_for_each_entry(h, &ip_tproxy_bylocal[hash], list) {
		sr = h->sockref;

		DEBUGP(KERN_DEBUG "IP_TPROXY: sockref_cmpfn_local(): sr: %08x:%04x "
		       "(foreign: %08x:%04x remote: %08x:%04x), searched: "
		       "%08x:%04x (remote: %08x:%04x)\n", 
		       sr->laddr, sr->lport, sr->faddr, sr->fport,
		       sr->raddr, sr->rport, addr, port, raddr, rport);

		if (sr->laddr == addr && sr->lport == port && sr->proto == proto) {
			/* fresh means orphaned entries should be skipped */
			if (fresh && (sr->flags & TF_ORPHAN))
				continue;

			if (raddr == 0 && rport == 0) {
				/* not interested in remote address */
				return sr;
			}
			else if (sr->raddr == raddr && sr->rport == rport) {
				/* complete match */
				return sr;
			}
			else if (sr->raddr == 0 && sr->rport == 0) {
				/* unconnected sockref if complete match not found */
				best = sr;
			}
		}
	}
	
	return best;
}

/* lookup sockref based on the foreign address. refcount is not incremented on
 * the returned sockref */
struct ip_tproxy_sockref *
ip_tproxy_sockref_find_foreign(u32 addr, u16 port, u8 proto, u32 raddr, u16 rport)
{
	u32 hash = ip_tproxy_hash_fn(addr, port, proto);
	struct ip_tproxy_hash *h;
	struct ip_tproxy_sockref *sr, *best = NULL;

	ASSERT_READ_LOCK(&ip_tproxy_byforeign[hash]);
	DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_sockref_find_foreign(): "
	       "entered, %08x:%04x\n", addr, port);

	list_for_each_entry(h, &ip_tproxy_byforeign[hash], list) {
		sr = h->sockref;

		DEBUGP(KERN_DEBUG "IP_TPROXY: sockref_cmpfn_foreign(): sr: %08x:%04x "
		       "(remote: %08x:%04x), searched: %08x:%04x "
		       "(remote: %08x:%04x)\n", 
		       sr->faddr, sr->fport, sr->raddr, sr->rport, addr, port, raddr, rport);

		if (sr->faddr == addr && sr->fport == port && sr->proto == proto) {
			if (raddr == 0 && rport == 0) {
				/* not interested in remote address */
				return sr;
			}
			else if (sr->raddr == raddr && sr->rport == rport) {
				/* complete match */
				return sr;
			}
			else if (sr->raddr == 0 && sr->rport == 0) {
				/* unconnected sockref if complete match not found */
				best = sr;
			}
		}
	}

	return best;
}

/* delete all sockrefs currently in the hash tables
 * FIXME: we might have a race here. If our hook is running while to module is
 * unloading, bad things might happen. */
static void
ip_tproxy_sockref_table_free(void)
{
	int i;
	struct ip_tproxy_hash *h, *p;

	for (i = 0; i < ip_tproxy_htable_size; i++) {
		list_for_each_entry_safe(h, p, &ip_tproxy_bylocal[i], list) {
			list_del(&h->list);
			ip_tproxy_kill_conntracks(h->sockref, 0, 0, 0);
			ip_tproxy_sockref_unref(h->sockref);
		}
		ip_tproxy_byforeign[i].prev = ip_tproxy_byforeign[i].next = &ip_tproxy_byforeign[i];
	}
}

/* determine ip address of the interface the packet came in */
static u32
ip_tproxy_determine_local_ip(struct sk_buff *skb, int hooknum)
{
        struct in_device *indev;
        u32 ip;
        
        if (hooknum == NF_IP_LOCAL_OUT)
        	return htonl(0x7f000001);
        
        indev = in_dev_get(skb->dev);
        
        if (!indev) {
                printk(KERN_WARNING "IP_TPROXY: No IP protocol on incoming "
		       "interface during redirect, dropping packet.\n");
                return 0;
        }
        if (!indev->ifa_list) {
                printk(KERN_WARNING "IP_TPROXY: No IP address on incoming "
		       "interface during redirect, dropping packet.\n");
                in_dev_put(indev);
                return 0;
        }
        
        ip = indev->ifa_list->ifa_local;
        in_dev_put(indev);
        
        return ip;
}

/* setup a bidirectional NAT mapping for the given connection, using the values specified by
 * the assigned sockref */
static int
ip_tproxy_setup_nat_bidir(struct ip_conntrack *ct, int hooknum, struct ip_tproxy_sockref *sr, unsigned int flags)
{
	struct ip_nat_multi_range mr;
        struct ip_nat_info *info = &ct->nat.info;
        u32 newip = 0;
	u16 newport = 0;
	int res, initialized = info->initialized;
	
	if (is_confirmed(ct) || (initialized & (1 << HOOK2MANIP(hooknum)))) {
		return NF_ACCEPT;
	}
	
	DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_setup_nat(): adding nat "
	       "entry hooknum=%d %08x:%04x -> %08x:%04x\n", hooknum, sr->laddr,
	       sr->lport, sr->faddr, sr->fport);

	mr.rangesize = 1;
	mr.range[0].flags = IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_BYPASS_HELPERS;
	
	if (hooknum == NF_IP_POST_ROUTING) {
		/* in POSTROUTING we perform an SNAT to the foreign address */
		newip = sr->faddr;
		newport = sr->fport;
	} 
	else if (hooknum == NF_IP_PRE_ROUTING || hooknum == NF_IP_LOCAL_OUT) {
		/* in PREROUTING and LOCAL_OUT we perform a DNAT to our socket address */
		
		newip = sr->laddr;
		newport = sr->lport;
	}

	mr.range[0].min_ip = mr.range[0].max_ip = newip;

	/* if port number was specified */
	if (newport != 0) {
		if (sr->proto == IPPROTO_TCP) {
			mr.range[0].min.tcp.port = mr.range[0].max.tcp.port = newport;
			mr.range[0].flags |= IP_NAT_RANGE_PROTO_SPECIFIED;
		}
		else if (sr->proto == IPPROTO_UDP) {
			mr.range[0].min.udp.port = mr.range[0].max.udp.port = newport;
			mr.range[0].flags |= IP_NAT_RANGE_PROTO_SPECIFIED;
		}
#ifdef CONFIG_IP_NF_NAT_NRES
		if (sr->flags & TF_NAT_RESERVED)
			mr.range[0].flags |= IP_NAT_RANGE_USE_RESERVED;
#endif
	}
	

	MUST_BE_READ_WRITE_UNLOCKED(&ip_nat_lock);
	WRITE_LOCK(&ip_nat_lock);
	res = ip_nat_setup_info(ct, &mr, hooknum);
	WRITE_UNLOCK(&ip_nat_lock);

	if (res != NF_ACCEPT) {
		printk(KERN_WARNING "IP_TPROXY: error applying NAT mapping, "
		       "hooknum=%d %08x:%04x -> %08x:%04x\n",
		       hooknum, sr->laddr, sr->lport, newip, newport);
	}
	else {
		/* we store a reference to the sockref in the conntrack */
		if (!test_and_set_bit(IPS_TPROXY_BIT, &ct->status)) {
			if (flags & TN_STOREREF) {
				ip_tproxy_sockref_ref(sr);
				ct->tproxy.sockref = sr;
			}
		}

		if ((newport == 0) && (info->num_manips > 0) && (sr->flags & TF_HASHED)) {
			u16 fport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
			WRITE_LOCK(&ip_tproxy_lock);
			ip_tproxy_rehash_fport(sr, fport);
			WRITE_UNLOCK(&ip_tproxy_lock);
		}
	}

	DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_setup_nat(): after setupinfo, "
	       "%p, %p\n", info->bysource.list.prev, info->bysource.list.next);

	return res;
}

/* redirect incoming packet to the appropriate local port (UDP specific) */
static int
ip_tproxy_setup_nat_unidir(struct sk_buff **pskb, int hooknum, struct ip_tproxy_sockref *sr)
{
	enum ip_nat_manip_type manip_type;
	struct sk_buff *skb = *pskb;
        u32 newip = 0;
	u16 newport = 0;
	struct ip_conntrack_manip manip;
	
	/* free the original conntrack entry, and assign the fake one */
	nf_conntrack_put(skb->nfct);
	skb->nfct = &ip_tproxy_fake_ct.infos[IP_CT_NEW];
	nf_conntrack_get(skb->nfct);
	skb->nfcache = NFC_ALTERED;
	
	/* this is our own conntrack entry now */

	if (hooknum == NF_IP_POST_ROUTING) {
		/* in POSTROUTING we perform an SNAT to the foreign address */
		newip = sr->faddr;
		newport = sr->fport;
		manip_type = IP_NAT_MANIP_SRC;
	} 
	else if (hooknum == NF_IP_PRE_ROUTING || hooknum == NF_IP_LOCAL_OUT) {
		/* in PREROUTING and LOCAL_OUT we perform a DNAT to our socket address */
		
		newip = sr->laddr;
		newport = sr->lport;
		manip_type = IP_NAT_MANIP_DST;
	}
	else 
		return NF_DROP;
	manip.ip = newip;
	manip.u.udp.port = newport;
	
	/* manipulate packet "by hand" */
	READ_LOCK(&ip_nat_lock);
	/* if the skb is cloned, create a copy before modifying */
	if (skb_cloned(skb) && !(skb->sk)) {
		struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
		if (!nskb) {
			READ_UNLOCK(&ip_nat_lock);
			return NF_DROP;
		}
		kfree_skb(skb);
		*pskb = skb = nskb;
	}
	ip_nat_manip_pkt(skb->nh.iph->protocol, skb->nh.iph, skb->len,
			 &manip, manip_type, &skb->nfcache);
	READ_UNLOCK(&ip_nat_lock);
	return NF_ACCEPT;
}

/* setup NAT for the packet */
static int
ip_tproxy_setup_nat(struct sk_buff **pskb, int hooknum, struct ip_tproxy_sockref *sr, unsigned int flags)
{
  
	if (sr->proto == IPPROTO_TCP || (flags & TN_BIDIR)) {
		struct ip_conntrack *ct;
		enum ip_conntrack_info ctinfo;
      
		ct = ip_conntrack_get(*pskb, &ctinfo);
		return ip_tproxy_setup_nat_bidir(ct, hooknum, sr, flags);
	}
	else if (sr->proto == IPPROTO_UDP)
		return ip_tproxy_setup_nat_unidir(pskb, hooknum, sr);
	return NF_DROP;
}

/* This is a gross hack */
static void
ip_tproxy_save_orig_addrs(struct sk_buff *skb)
{
 	struct iphdr *iph = skb->nh.iph;
	u16 tports[2];
	
        if (iph->protocol==IPPROTO_UDP && (IPCB(skb)->flags & IPSKB_MASQUERADED))
           return;

	if (skb_copy_bits(skb, iph->ihl * 4, &tports, sizeof(u16) * 2) >= 0) {
		IPCB(skb)->orig_srcaddr = iph->saddr;
		IPCB(skb)->orig_srcport = tports[0];
		IPCB(skb)->orig_dstaddr = iph->daddr;
		IPCB(skb)->orig_dstport = tports[1];
	}
}

/* tproxy Netfilter hook */
static unsigned int
ip_tproxy_fn(unsigned int hooknum,
             struct sk_buff **pskb,
             const struct net_device *in,
             const struct net_device *out,
             int (*okfn)(struct sk_buff *))
{
        struct ip_conntrack *ct;
        enum ip_conntrack_info ctinfo;
        unsigned int verdict = NF_ACCEPT;

	if ((*pskb)->nh.iph->frag_off & htons(IP_MF|IP_OFFSET)) {
		*pskb = ip_ct_gather_frags(*pskb, NF_IP_POST_ROUTING);

		if (!*pskb)
			return NF_STOLEN;
	}

	ct = ip_conntrack_get(*pskb, &ctinfo);
	
	//if (ct && ctinfo == IP_CT_NEW) {
        if ((ct && ctinfo == IP_CT_NEW) || (ct && ctinfo == IP_CT_RELATED)) {
		struct iphdr *iph = (*pskb)->nh.iph;
		u16 tports[2];
		struct ip_tproxy_sockref *sr = NULL;

		if (skb_copy_bits(*pskb, (*pskb)->nh.iph->ihl*4, &tports, sizeof(u16) * 2) < 0) {
			DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_fn(): "
			       "failed to copy protocol header\n");
			return NF_DROP;
		}
		
		DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_fn(): new connection, "
		       "hook=%d, %08x:%04x -> %08x:%04x\n",
		       hooknum, iph->saddr, tports[0], iph->daddr, tports[1]);

		ip_tproxy_save_orig_addrs(*pskb);
		READ_LOCK(&ip_tproxy_lock);
		if (hooknum == NF_IP_PRE_ROUTING || hooknum == NF_IP_LOCAL_OUT) {
		
			/* 
			 * We either received a connection from the network (PREROUTING case)
			 * or a local process generated one (LOCAL_OUT case).
			 *
			 * In either case we check whether a proxy bound to the
			 * destination of this connection.
			 *
			 * As a special case we check in LOCAL_OUT whether the
			 * connection was initiated by a local proxy, and if it
			 * was we mark the connection as such and skip the 
			 * tproxy table.
			 */
			 
			/* destination address is interesting */
			
			sr = ip_tproxy_sockref_find_foreign(iph->daddr, tports[1],
						iph->protocol, iph->saddr, tports[0]);
			
			if (sr && sr->flags & TF_ORPHAN) {
				/* This sockref is orphaned, the listening socket is already unassigned,
				 * so it should not be used for setting up NAT for a new connection. */
				sr = NULL;
			}

			if (sr && (sr->flags & (TF_LISTEN|TF_MARK_ONLY)) == 0) {
				DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_fn(PREROUTING), "
				       "entry found but flags = 0\n");
				sr = NULL;
			}

			if (hooknum == NF_IP_LOCAL_OUT && 
			    !sr && 
			    (sr = ip_tproxy_sockref_find_local(iph->saddr, tports[0],
							       iph->protocol, 1, iph->daddr,
							       tports[1]))) {
				DEBUGP(KERN_DEBUG "IP_TPROXY: tproxy initiated session in local "
				       "output, sr->flags=%04x\n", sr->flags);
				if ((sr->flags & TF_MARK_ONLY) == 0)
					sr = NULL;
			}
		}
		else if (hooknum == NF_IP_POST_ROUTING) {
		
			/*
			 * We detected a new connection just leaving this box, so
			 * we now have a chance to add a translation changing
			 * the source address of all packets. We want to do this
			 * if the connection was initiated by a transparent proxy
			 * which registered another address to rewrite the source into.
			 *
			 * A proxy registered an entry if find_local returns non-NULL.
			 */
		
			/* source address is interesting */
			
			sr = ip_tproxy_sockref_find_local(iph->saddr, tports[0], iph->protocol,
					1, iph->daddr, tports[1]);
			if (sr && (sr->flags & (TF_CONNECT|TF_MARK_ONLY)) == 0) {
				DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_fn(POSTROUTING), "
				       "entry found but flags = 0\n");
				sr = NULL;
			}
		}
		else {
			printk(KERN_WARNING "IP_TPROXY: hook function called at hooks other "
			       "than NF_IP_PRE_ROUTING, NF_IP_POST_ROUTING or "
			       "NF_IP_LOCAL_OUT, hooknum=%d\n", hooknum);
			verdict = NF_DROP;
		}
		
		/* 
		 * sockref will not be freed, as the hash is read locked here
		 * and by the time we unlock it we own a reference 
		 */

		if (sr) {
			if (sr->flags & TF_MARK_ONLY) {
				/*
				 * A MARK_ONLY entry indicates that although the proxy
				 * doesn't want any address rewrite to be performed
				 * it registered its connection as one originating
				 * from a transparent proxy, so -m tproxy matches it.
				 *
				 * It is a convinience feature, so administrators
				 * can simply let tproxied traffic through their filter
				 * table.
				 */
				DEBUGP(KERN_DEBUG "IP_TPROXY: mark only entry...\n");

				if (!test_and_set_bit(IPS_TPROXY_BIT, &ct->status))
					ct->tproxy.sockref = NULL;

				sr = NULL;
			}
			else {
				/* we'll have a reference to the sockref after releasing the lock */
				ip_tproxy_sockref_ref(sr);
			}
		}
		READ_UNLOCK(&ip_tproxy_lock);
		
		DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_fn(): sockref looked up, sr=%p\n", sr);
		if (sr) {
		
			/* sockref found it is a real translation as
			 * MARK_ONLY was handled above so we apply the
			 * necessary NAT function 
			 */

			/* apply NAT mapping */
			unsigned int dirflag = !(sr->flags & TF_UNIDIR) ? TN_BIDIR : 0;
			if (ip_tproxy_setup_nat(pskb, hooknum, sr, dirflag | TN_STOREREF) == NF_ACCEPT) {
				/* FIXME: hmm. there might be races involved
				 * with TF_NAT_APPLIED, as another processor
				 * might be processing the same sockref.
				 */
				sr->flags |= TF_NAT_APPLIED;
                                if ((*pskb)->nh.iph && (*pskb)->nh.iph->protocol==IPPROTO_UDP) {
                                   IPCB((*pskb))->flags |= IPSKB_MASQUERADED;
                                }
			} else {
				/* Applying the NAT mapping failed, we should drop the packet */
				verdict = NF_DROP;
			}

			/* drop reference */
			ip_tproxy_sockref_unref(sr);
		} /* if (sr) */
		else if (!test_bit(IPS_TPROXY_BIT, &ct->status) && 
			 (hooknum == NF_IP_PRE_ROUTING || hooknum == NF_IP_LOCAL_OUT)) {

                	struct ipt_tproxy_user_info ui;
                	
                	/* there was no matching sockref, so we consult the 
                	 * TPROXY table 
                	 */
                	
			ui.changed = 0;
                        verdict = ipt_do_table(pskb, hooknum, in, out, &tproxy_table, &ui);
                        if (ui.changed && verdict == NF_ACCEPT) {
                        	struct ip_tproxy_sockref sr;
                        	u32 laddr;
                        	u16 lport;
                        	
                        	/* packet was redirected */
				if (ui.lport == 0)
					lport = tports[1];
				else
					lport = ui.lport;
					
				if (ui.laddr == 0)
					laddr = ip_tproxy_determine_local_ip(*pskb, hooknum);
				else
					laddr = ui.laddr;
				
				memset(&sr, 0, sizeof(sr));
				
				DEBUGP(KERN_DEBUG "IP_TPROXY: performing redirect to %08x:%04x\n",
				       sr.laddr, sr.lport);

				sr.laddr = laddr;
				sr.lport = lport;
				sr.proto = iph->protocol;
				if (!ip_tproxy_setup_nat(pskb, hooknum, &sr, 0))
					verdict = NF_DROP;
                                else {
                                        if ((*pskb)->nh.iph && (*pskb)->nh.iph->protocol==IPPROTO_UDP) {
                                           IPCB((*pskb))->flags |= IPSKB_MASQUERADED;
                                        }
                                }
			}
		}
	} else {
		u8 tcp_flags = 0;
		if (skb_copy_bits(*pskb, (*pskb)->nh.iph->ihl*4 + 13, &tcp_flags, 1) >= 0)
			if (tcp_flags == 2) // syn packet
				ip_tproxy_save_orig_addrs(*pskb);
	}

	return verdict;
}

/* hack: get layer 3 protocol type */
static inline int
ip_tproxy_get_sk_proto(struct sock *sk)
{
	/* FIXME: this is insane, I've seen crashes where
	 * sk->prot == NULL, so we have to check before accessing
	 * its fields. */
	if (sk->prot == NULL ||
	    sk->prot->name == NULL)
		return 0;
	
	if (strcmp(sk->prot->name, "TCP") == 0)
        	return IPPROTO_TCP;
	else if (strcmp(sk->prot->name, "UDP") == 0)
		return IPPROTO_UDP;
	else
		return 0;
}

#ifdef CONFIG_IP_NF_NAT_NRES
static inline struct ip_nat_reserved *
ip_tproxy_nat_reserve(const u32 faddr, const u16 fport, int proto, const u32 raddr, const u16 rport)
{
	struct ip_conntrack_manip m = {.ip = faddr, .u = {.all = fport}};
	struct ip_conntrack_manip p = {.ip = raddr, .u = {.all = rport}};
	struct ip_nat_reserved *res;

	DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_nat_reserve proto %u foreign "
	       "%u.%u.%u.%u:%u peer %u.%u.%u.%u:%u\n",
	       proto, NIPQUAD(faddr), ntohs(fport), NIPQUAD(raddr), ntohs(rport));

	WRITE_LOCK(&ip_nat_lock);
	res = __ip_nat_reserved_new_hash(&m, proto, (raddr && rport) ? &p : NULL);
	WRITE_UNLOCK(&ip_nat_lock);

	return res;
}

static void
ip_tproxy_nat_reserved_free(struct ip_tproxy_sockref *sr)
{
	struct ip_nat_reserved *res;
	struct ip_conntrack_manip m = {.ip = sr->faddr, .u = {.all = sr->fport}};
	struct ip_conntrack_manip p = {.ip = sr->raddr, .u = {.all = sr->rport}};

	/* free NAT reservation */
	if (sr->flags & TF_NAT_RESERVED) {
		WRITE_LOCK(&ip_nat_lock);
		if (sr->flags & TF_NAT_PEER)
			res = __ip_nat_reserved_unhash(&m, sr->proto, &p);
		else
			res = __ip_nat_reserved_unhash(&m, sr->proto, NULL);
		WRITE_UNLOCK(&ip_nat_lock);

		if (res) {
			sr->flags &= ~(TF_NAT_RESERVED | TF_NAT_PEER);
			__ip_nat_reserved_free(res);
		}
	}
}
#endif

/* This routine dynamically allocates a foreign port if the proxy requests this
 * by setting fport to 0. We try to use the same algorithm the local stack
 * uses to allocate a port. The routine itself is only used when we need to
 * allocate a foreign port _before_ sending the first packet, standard connect
 * sockets get their foreign port allocated by the NAT subsystem. */
static inline int
ip_tproxy_sockref_uniq(struct ip_tproxy_sockref *sr)
{
	int min, max, rover, left;
	static int ip_tproxy_port_rover = 0;

	MUST_BE_WRITE_LOCKED(&ip_tproxy_lock);
	
	DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_sockref_uniq\n");
	min = sysctl_local_port_range[0];
	max = sysctl_local_port_range[1];
	rover = ip_tproxy_port_rover;
	left = (max - min) + 1;
	do {
		rover++;
		if (rover < min || rover > max)
			rover = min;
		if (ip_tproxy_sockref_find_foreign(sr->faddr, htons(rover),
		    sr->proto, sr->raddr, sr->rport) == NULL) {
#ifdef CONFIG_IP_NF_NAT_NRES
			/* unique entry found, try to reserve in NAT */
			if (ip_tproxy_nat_reserve(sr->faddr, htons(rover),
				sr->proto, sr->raddr, sr->rport))
#endif
				break;
		}
	} while (--left > 0);

	if (left == 0) {
		printk(KERN_WARNING "IP_TPROXY: out of free foreign ports, "
		       "increase local_port_range\n");
		return 0;
	} else if (rover == 0) {
		printk(KERN_WARNING "IP_TPROXY: hm?? ip_tproxy_sockref_uniq, "
		       "left != 0 && rover == 0\n");
	} else {
		/* succeeded */
		DEBUGP(KERN_DEBUG "IP_TPROXY: ip_tproxy_sockref_uniq, "
		       "allocated port=%d\n", rover);

		ip_tproxy_port_rover = rover;

#ifdef CONFIG_IP_NF_NAT_NRES
		sr->flags |= TF_NAT_RESERVED;
		if (sr->raddr && sr->rport)
			sr->flags |= TF_NAT_PEER;
#endif
		ip_tproxy_rehash_fport(sr, htons(rover));
	}

	return rover;
}

static int
ip_tproxy_setsockopt_version(struct sock *sk, int proto, struct in_tproxy *itp)
{
	int res = 0;
	u_int32_t ver = itp->v.version;

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_VERSION\n");

	if ((MAJOR_VERSION(ver) != TPROXY_MAJOR_VERSION) ||
	    (MINOR_VERSION(ver) > TPROXY_MINOR_VERSION))
		res = -EINVAL;

	return res;
}

static int
ip_tproxy_setsockopt_assign(struct sock *sk, int proto, struct in_tproxy *itp)
{
	int foreign_matches, res = 0;
	struct ip_tproxy_sockref *sr, *tsr = NULL;

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_ASSIGN %08x:%04x\n",
	       sk->rcv_saddr, sk->sport);

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (sk->socket->state != SS_UNCONNECTED) {
		DEBUGP(KERN_DEBUG "IP_TPROXY: socket is not SS_UNCONNECTED "
		       "during assign\n");
		return -EINVAL;
	}

	if (!sk->rcv_saddr || !sk->sport)
		return -EINVAL;

	READ_LOCK(&ip_tproxy_lock);

	DEBUGP(KERN_DEBUG "IP_TPROXY: count=%d\n", ip_tproxy_htable_count);

        /* check if this socket was already assigned a sockref */
        sr = ip_tproxy_sockref_find_local(sk->rcv_saddr, sk->sport, proto, 0, 0, 0);

	/* NOTE: this is a HACK, and trusts the userspace app.
	   We allow to assign multiple sockrefs to a single
	   local addr:port pair _iff_ the foreign address is
	   0.0.0.0:0 to allow UDP sessions to be bound to
           the same socket while keeping the 'mark as
           tproxy' packet mechanism.

	   Maybe we should assign sockrefs to the struct sock * 
	   address instead.
	*/
	if (sr) {
		if (itp->v.addr.faddr.s_addr || itp->v.addr.fport) {
			printk("IP_TPROXY: socket already assigned, reuse=%d, "
			       "%08x:%04x, sr->faddr=%08x:%04x, flags=%x, "
			       "sr->tv_hashed=%ld:%ld\n", sk->reuse, 
			       sk->rcv_saddr, sk->sport, sr->faddr, sr->fport,
			       sr->flags, sr->tv_hashed.tv_sec, sr->tv_hashed.tv_usec);
			res = -EEXIST;
			goto read_unlk;
		} else {
			DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_ASSIGN local address "
			       "already taken, sharing this sockref\n");

			/* increase socket count of sockref, indicating that it is
			 * shared between multiple sockets */
			atomic_inc(&sr->socket_count);
			goto read_unlk;
		}
	}

	/* check if the foreign address specified has already been taken.
	 * if it has, the socket can only be used for connecting, provided
	 * sk->reuse is true, otherwise fail */

	if (itp->v.addr.faddr.s_addr && itp->v.addr.fport != 0 &&
	    (tsr = ip_tproxy_sockref_find_foreign(itp->v.addr.faddr.s_addr,
						  itp->v.addr.fport, proto, 0, 0))) {
		if (!sk->reuse) {
			res = -EADDRINUSE;
			goto read_unlk;
		}
		foreign_matches = 1;
	} else {
		foreign_matches = 0;
	}

	/* we performed all checks, now allocate and fill a new
	 * sockref */

	sr = ip_tproxy_sockref_new();
	if (!sr) {
		printk(KERN_WARNING "IP_TPROXY: drained? cannot allocate sockref\n");
		res = -ENOBUFS;
		goto read_unlk;
	}
	sr->flags = 0;
	sr->proto = proto;
	sr->faddr = itp->v.addr.faddr.s_addr;
	sr->fport = itp->v.addr.fport;
	sr->laddr = sk->rcv_saddr;
	sr->lport = sk->sport;
	sr->assigned_to = sk;

	if (itp->v.addr.faddr.s_addr == 0) {
		/* we store the local address as foreign as well
		 * for mark only connections, so find_foreign
		 * finds this entry as well */
		
		sr->flags |= TF_MARK_ONLY;
		sr->faddr = sr->laddr;
		sr->fport = sr->lport;
	} else if (foreign_matches) {
		/* sk->reuse was true */
		/* if the existing sockref is mark only, or has its remote
		 * endpoint specified, we have a chance not to clash with it,
		 * otherwise this sockref will be connect-only */

		if ((tsr->flags & TF_MARK_ONLY) || (tsr->raddr != 0 && tsr->rport != 0)) {
			DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_ASSIGN omitting "
			       "CONNECT_ONLY, other sockref is mark-only or connected\n");
		} else {
			sr->flags |= TF_CONNECT_ONLY;
			DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_ASSIGN setting "
			       "sr %p CONNECT_ONLY\n", sr);
		}
	}

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_ASSIGN sr %p faddr:fport "
	       "%08x:%04x flags %08x\n", sr, sr->faddr, sr->fport, sr->flags);

#ifdef CONFIG_IP_NF_NAT_NRES
	/* If SO_REUSE is not set and foreign port was specified, we should
	 * allocate a NAT reservation right now. This mode is used by range
	 * binds, so being pessimistic at NAT reservation clash checks causes
	 * the caller to proceed to the next port and try again. */
	if (itp->v.addr.faddr.s_addr && itp->v.addr.fport &&
	    !foreign_matches && !sk->reuse) {
		/* we should register a NAT reservatinon */
		if (ip_tproxy_nat_reserve(sr->faddr, sr->fport, proto, 0, 0)) {
			sr->flags |= TF_NAT_RESERVED;
			sr->flags &= ~TF_NAT_PEER;
		} else {
			/* failed to register NAT reservation, bail out */
			DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_ASSIGN cannot "
			       "register NAT reservation %08x:%04x\n",
			       sr->faddr, sr->fport);

			res = -EINVAL;
			ip_tproxy_sockref_unref(sr);
			goto read_unlk;
		}
	}
#endif

	READ_UNLOCK(&ip_tproxy_lock);
	WRITE_LOCK(&ip_tproxy_lock);
	/* here we should check if we've won the race: if a sockref is in the
	 * local hash by the time we acquired the write lock, we've lost */
	if (!(tsr = ip_tproxy_sockref_find_local(sk->rcv_saddr, 
						 sk->sport, proto, 0, 0, 0)))
		ip_tproxy_hash(sr);
	WRITE_UNLOCK(&ip_tproxy_lock);

	if (tsr) {
		/* we've lost the race */
		res = -EINVAL;
	}

	/* the hashtable stores a reference, if hashing succeeded */
	ip_tproxy_sockref_unref(sr);

	return res;

 read_unlk:
	READ_UNLOCK(&ip_tproxy_lock);
	return res;
}

static int
ip_tproxy_setsockopt_unassign(struct sock *sk, int proto, struct in_tproxy *itp)
{
	int res = 0, unhash = 0;
	struct ip_tproxy_sockref *sr;

	/* break the connection between this socket and
	 * a foreign address. This is implicitly performed
	 * when the socket is closed */

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_UNASSIGN %08x:%04x\n",
	       sk->rcv_saddr, sk->sport);

	WRITE_LOCK(&ip_tproxy_lock);
	sr = ip_tproxy_sockref_find_local(sk->rcv_saddr, sk->sport, proto,
					  0, sk->daddr, sk->dport);

	if (!sr) {
		DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_UNASSIGN not unhashing socket, "
				  "%08x:%04x, proto=%d, sk->state=%d\n",
				  sk->rcv_saddr, sk->sport, proto, sk->state);
		res = -ENOENT;
		goto write_unlk;
	}

	/* Delete appropriate related connections and set 'unhash' if
	 * we have to unhash the sockref. */

	/* Handle mark-only sockrefs separately: mark-only sockrefs don't have
	 * related conntrack entries, so there is no need to bother to delete
	 * the correct one from the related list. However, mark-only entries
	 * can be shared, which means that more than one sockets are bound to
	 * the same local address, and they are using the same sockref to have
	 * matching connections marked. Because of this, we may unhash the
	 * sockref only if there are no sockets left */
	if (sr->flags & TF_MARK_ONLY) {
		DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_UNASSIGN unassigning "
		       "mark-only sockref %08x:%04x\n", sk->rcv_saddr, sk->sport);
		if (atomic_dec_and_test(&sr->socket_count)) {
			/* this was the last socket using this sockref */
			unhash = 1;
		}
	} else switch (proto) {
	case IPPROTO_TCP:
		if ((sr->flags & TF_LISTEN)) {
			if (sr->assigned_to != sk) {
				/* unassigning the socket of a connection
				 * established to a listening socket */
				DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_UNASSIGN unassigning "
				       "TCP listen related %08x:%04x -> %08x:%04x\n",
				       sk->daddr, sk->dport, sk->rcv_saddr, sk->sport);
			} else {
				/* unassigning a listening socket, don't destroy just mark invalid */
				DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_UNASSIGN unassigning "
				       "TCP listen socket %08x:%04x\n",
				       sk->rcv_saddr, sk->sport);
				sr->flags |= TF_ORPHAN;
				sr->assigned_to = NULL;
			}

			/* we have to unhash if there are no more related
			 * connections and the listening socket is closed as
			 * well */
			if (!atomic_read(&sr->related) && !sr->assigned_to)
				unhash = 1;

		} else if (sr->flags & TF_CONNECT) {
			/* unassigning a connect socket */
			DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_UNASSIGN unassigning "
			       "TCP connect %08x:%04x\n", sk->rcv_saddr, sk->sport);
			unhash = 1;
		}
		break;

	case IPPROTO_UDP:
		DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_UNASSIGN unassigning UDP "
		       "%08x:%04x\n", sk->rcv_saddr, sk->sport);
		ip_tproxy_kill_conntracks(sr, 0, 0, 1);
		unhash = 1;
		break;
	}

	/* unhash sockref if we don't need it anymore */
	if (unhash) {
#ifdef CONFIG_IP_NF_NAT_NRES
		ip_tproxy_nat_reserved_free(sr);
#endif
		ip_tproxy_unhash(sr);
	}

 write_unlk:
	WRITE_UNLOCK(&ip_tproxy_lock);

	return res;
}

static int
ip_tproxy_setsockopt_flags(struct sock *sk, int proto, struct in_tproxy *itp)
{
	int res = 0;
	struct ip_tproxy_sockref *sr;
	u_int32_t flags = itp->v.flags;

	/* specify translation flags for this socket */

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS %08x:%04x\n",
	       sk->rcv_saddr, sk->sport);

	/* we don't check CAP_NET_ADMIN here, it was checked when this entry was hashed */

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS flags to set %08x\n",
	       flags);

	/* since read locks cannot be upgraded, we need a write lock if
	 * foreign port allocation will be needed... */
	WRITE_LOCK(&ip_tproxy_lock);
	sr = ip_tproxy_sockref_find_local(sk->rcv_saddr, sk->sport, proto,
					  0, sk->daddr, sk->dport);
	if (!sr) {
		res = -ENOENT;
		goto write_unlk;
	}

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS sr %p flags %08x\n", sr, sr->flags);

	/* Don't do anything in case of MARK_ONLY sockrefs */
	if (sr->flags & TF_MARK_ONLY) {
		DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS sr %p mark only, "
		       "doing nothing\n", sr);
		goto write_unlk;
	}

	/* clear user-settable flags */
	sr->flags &= TF_STATE_MASK;

	/* set TF_CONNECT/TF_LISTEN if needed */
	switch (flags & (ITP_CONNECT | ITP_LISTEN | ITP_ESTABLISHED)) {
	case ITP_CONNECT:
		sr->flags |= TF_CONNECT;
		ip_tproxy_kill_conntracks(sr, 0, 0, 1);
		break;

	case ITP_LISTEN:
		if (sr->flags & TF_CONNECT_ONLY) {
			DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS sr %p: "
			       "trying to set ITP_LISTEN on a connect only sockref\n", sr);
			res = -EINVAL;
			break;
		}

		sr->flags |= TF_LISTEN;
		ip_tproxy_kill_conntracks(sr, 0, 0, 1);
		break;

	case ITP_ESTABLISHED:
		DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS: establishing sr %p "
		       "raddr:rport %08x:%04x daddr:dport %08x:%04x\n",
		       sr, sr->raddr, sr->rport, sk->daddr, sk->dport);

		if (sr->raddr == 0 || sr->rport == 0) {
			DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS sr %p: "
			       "trying to set ITP_ESTABLISHED on a not connected sockref\n",
			       sr);
			res = -EINVAL;
		}

		sr->flags |= TF_LISTEN | TF_CONNECT;
		ip_tproxy_kill_conntracks(sr, 0, 0, 1);
		break;

	default:
		DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS sr %p: "
		       "invalid combination of flags %x\n", sr, flags);
		/* FIXME: indicate error, if no CONNECT/LISTEN/ESTABLISHED was given? */
		break;
	}

	/* Set TF_NAT_ONCE and TF_UNIDIR if needed */
	sr->flags |= (flags & ITP_ONCE ? TF_NAT_ONCE : 0) | 
	             (flags & ITP_UNIDIR ? TF_UNIDIR : 0);

#ifdef CONFIG_IP_NF_NAT_NRES
	/* reserve NAT mappings if connecting and sk->reuse is set */
	if (sr->flags & TF_CONNECT && sr->faddr && sr->fport && sk->reuse) {
		if (ip_tproxy_nat_reserve(sr->faddr, sr->fport, proto, sr->raddr, sr->rport)) {
			sr->flags |= (TF_NAT_RESERVED | TF_NAT_PEER);
		} else {
			DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS sr %p: "
			       "failed to register NAT reservation\n", sr);
			res = -EINVAL;
			goto write_unlk;
		}
	}
#endif

 write_unlk:
	WRITE_UNLOCK(&ip_tproxy_lock);
	
	return res;
}

static int
ip_tproxy_setsockopt_alloc(struct sock *sk, int proto, struct in_tproxy *itp)
{
	int res = 0;
	struct ip_tproxy_sockref *sr;

	/* we'd like to force allocation of a unique foreign address, if one's
	 * not specified */
	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_ALLOC %08x:%04x\n",
	       sk->rcv_saddr, sk->sport);

	WRITE_LOCK(&ip_tproxy_lock);
	sr = ip_tproxy_sockref_find_local(sk->rcv_saddr, sk->sport, proto,
					  0, sk->daddr, sk->dport);
	if (!sr) {
		res = -ENOENT;
		goto write_unlk;
	}

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_ALLOC sr %p, current foreign "
	       "%08x:%04x\n", sr, sr->faddr, sr->fport);

	if (sr->flags & TF_MARK_ONLY) {
		DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_ALLOC sr %p mark only, "
		       "doing nothing\n", sr);
		goto write_unlk;
	}

	if (sr->faddr && sr->fport) {
		/* foreign port already assigned */
		res = -EINVAL;
		goto write_unlk;
	}

	if (ip_tproxy_sockref_uniq(sr) == 0) {
		/* allocating a foreign port failed */
		DEBUGP(KERN_DEBUG "IP_TPROXY: failed to allocate foreign port "
		       "for listening sockref\n");
		res = -EFAULT;
		goto write_unlk;
	}

 write_unlk:
	WRITE_UNLOCK(&ip_tproxy_lock);

	return res;
}

static int
ip_tproxy_setsockopt_connect(struct sock *sk, int proto, struct in_tproxy *itp)
{
	int res = 0;
	struct ip_tproxy_sockref *sr;

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_CONNECT %08x:%04x\n",
	       sk->rcv_saddr, sk->sport);

	/* Look up in the local sockref hash */
	READ_LOCK(&ip_tproxy_lock);
	sr = ip_tproxy_sockref_find_local(sk->rcv_saddr, sk->sport, proto,
					  0, sk->daddr, sk->dport);
	if (!sr) {
		res = -ENOENT;
		goto read_unlk;
	}

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_CONNECT sr %p, current "
	       "raddr:rport %08x:%04x\n", sr, sr->raddr, sr->rport);

	if (sr->flags & TF_MARK_ONLY) {
		DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_CONNECT sr %p "
		       "mark only\n", sr);
		goto read_unlk;
	}

	/* store remote address */
	if (itp->v.addr.faddr.s_addr && itp->v.addr.fport) {
		sr->raddr = itp->v.addr.faddr.s_addr;
		sr->rport = itp->v.addr.fport;
		DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_CONNECT sr %p, "
		       "new raddr:rport %08x:%04x\n", sr, sr->raddr, sr->rport);
	}

 read_unlk:
	READ_UNLOCK(&ip_tproxy_lock);

	return res;
}

static int
ip_tproxy_setsockopt_proxy_data(struct sock *sk, int proto, struct in_tproxy *itp)
{
        int res = 0;
        struct ip_conntrack_tuple_hash *h;

        // Save the client_server tuple in the acc_server conntrack: In ftp passive semi-transparent,
        // there is no linked_session. Therefore in order to get the client, we need that tuple

        h = ip_conntrack_find_get(&itp->v.proxy_info.acc_server_tuple, NULL);

        if ( h == NULL ) {
           res = -ENOENT;
        }
        else {
           h->ctrack->redirect_tuple.src.ip = itp->v.proxy_info.client_server_tuple.src.ip;
           h->ctrack->redirect_tuple.src.u.tcp.port = itp->v.proxy_info.client_server_tuple.src.u.tcp.port;
           h->ctrack->redirect_tuple.dst.ip = itp->v.proxy_info.client_server_tuple.dst.ip;
           h->ctrack->redirect_tuple.dst.u.tcp.port = itp->v.proxy_info.client_server_tuple.dst.u.tcp.port;
           h->ctrack->port_to_redirect = itp->v.proxy_info.port_to_redirect; //port to redirect the data (slave) is kept in the master
           atomic_dec(&h->ctrack->ct_general.use);
        }

        return res;
}

static int
ip_tproxy_setsockopt_save_sport(struct sock *sk, int proto, struct in_tproxy *itp)
{
	int res = 0;

        sk->linked_session_sport = itp->v.proxy_info.client_server_tuple.src.u.all;
        DEBUGP(KERN_DEBUG "Save on the new socket the port : %d\n", sk->linked_session_sport);

	return res;
}

static int 
ip_tproxy_setsockopt(struct sock *sk, int optval, void *user, unsigned int len)
{
	int proto;
	int res = 0;
	unsigned int mlen;
	struct in_tproxy itp;

	/* get protocol number of the socket */
	if ((proto = ip_tproxy_get_sk_proto(sk)) == 0)
		return -EINVAL;
	
	if (len < sizeof(itp.op) + sizeof(itp.v.version))
		return -EINVAL;

	mlen = MIN(sizeof(itp), len);
	
	if (copy_from_user(&itp, user, mlen))
		return -EFAULT;

	switch (itp.op) {
		case TPROXY_VERSION:
			res = ip_tproxy_setsockopt_version(sk, proto, &itp);
			break;
		case TPROXY_ASSIGN:
			res = ip_tproxy_setsockopt_assign(sk, proto, &itp);
			break;
		case TPROXY_UNASSIGN:
			res = ip_tproxy_setsockopt_unassign(sk, proto, &itp);
			break;
		case TPROXY_FLAGS:
			res = ip_tproxy_setsockopt_flags(sk, proto, &itp);
			break;
		case TPROXY_ALLOC:
			res = ip_tproxy_setsockopt_alloc(sk, proto, &itp);
			break;
		case TPROXY_CONNECT:
			res = ip_tproxy_setsockopt_connect(sk, proto, &itp);
			break;
		case TPROXY_PROXY_DATA:
			res = ip_tproxy_setsockopt_proxy_data(sk, proto, &itp);
			break;
		case TPROXY_SAVE_SPORT:
			res = ip_tproxy_setsockopt_save_sport(sk, proto, &itp);
			break;
		default:
			res = -ENOPROTOOPT;
			break;
	}

	return res;
}	

static int
ip_tproxy_getsockopt_version(struct sock *sk, int proto, struct in_tproxy *itp)
{
	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_VERSION\n");

	itp->v.version = TPROXY_FULL_VERSION;

	return 0;
}

static int
ip_tproxy_getsockopt_query(struct sock *sk, int proto, struct in_tproxy *itp)
{
	int res = 0;
	struct ip_tproxy_sockref *sr;

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_QUERY %08x:%04x\n",
	       sk->rcv_saddr, sk->sport);

	READ_LOCK(&ip_tproxy_lock);
	
	sr = ip_tproxy_sockref_find_local(sk->rcv_saddr, sk->sport, proto,
					  0, sk->daddr, sk->dport);
	if (sr) {
		itp->v.addr.faddr.s_addr = sr->faddr;
		itp->v.addr.fport = sr->fport;
		DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_QUERY found sr %p "
		       "faddr:fport %08x:%04x\n", sr, sr->faddr, sr->fport);
	} else
		res = -ENOENT;

	READ_UNLOCK(&ip_tproxy_lock);

	return res;
}

static int
ip_tproxy_getsockopt_flags(struct sock *sk, int proto, struct in_tproxy *itp)
{
	int res = 0;
	u_int32_t flags;
	struct ip_tproxy_sockref *sr;

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS get %08x:%04x\n", 
	       sk->rcv_saddr, sk->sport);

	READ_LOCK(&ip_tproxy_lock);

	sr = ip_tproxy_sockref_find_local(sk->rcv_saddr, sk->sport, proto,
					  0, sk->daddr, sk->dport);
	if (!sr) {
		res = -ENOENT;
		goto read_unlk;
	}
			
	flags = 0;
	if ((sr->flags & (TF_CONNECT+TF_LISTEN)) == (TF_CONNECT+TF_LISTEN))
		flags |= ITP_ESTABLISHED;
	else if (sr->flags & TF_CONNECT)
		flags |= ITP_CONNECT;
	else if (sr->flags & TF_LISTEN)
		flags |= ITP_LISTEN;

	if (sr->flags & TF_UNIDIR)
		flags |= ITP_UNIDIR;
	if (sr->flags & TF_NAT_ONCE)
		flags |= ITP_ONCE;
	if (sr->flags & TF_MARK_ONLY)
		flags |= ITP_MARK;
	if (sr->flags & TF_NAT_APPLIED)
		flags |= ITP_APPLIED;

	DEBUGP(KERN_DEBUG "IP_TPROXY: IP_TPROXY_FLAGS found sr %p faddr:fport "
	       "%08x:%04x flags %08x\n", sr, sr->faddr, sr->fport, sr->flags);

	itp->v.flags = flags;

 read_unlk:
	READ_UNLOCK(&ip_tproxy_lock);

	return res;
}

static int 
ip_tproxy_getsockopt(struct sock *sk, int optval, void *user, int *len)
{
	int proto;
	int res = 0;
	unsigned int mlen;
	struct in_tproxy itp;

	if ((proto = ip_tproxy_get_sk_proto(sk)) == 0)
		return -EINVAL;

	if (*len < sizeof(itp.op) + sizeof(itp.v.version))
		return -EINVAL;

	mlen = MIN(sizeof(itp), *len);

	if (copy_from_user(&itp, user, mlen))
		return -EFAULT;

	switch (itp.op) {
		case TPROXY_VERSION:
			res = ip_tproxy_getsockopt_version(sk, proto, &itp);
			break;
		case TPROXY_QUERY:
			res = ip_tproxy_getsockopt_query(sk, proto, &itp);
			break;
		case TPROXY_FLAGS:
			res = ip_tproxy_getsockopt_flags(sk, proto, &itp);
			break;
		default:
			res = -ENOPROTOOPT;
			break;
	}

	/* copy data to userspace */
	/* FIXME: we do this even when res != 0, is this a problem? */
	if (copy_to_user(user, &itp, mlen))
		res = -EFAULT;

	return res;
}	

/* callback function: called when a socket gets unhashed by the UDP or TCP
 * stack */
static void
ip_tproxy_close(struct sock *sk, int proto)
{
	if (proto)
		ip_tproxy_setsockopt_unassign(sk, proto, NULL);
}

/* fake timeout function needed by the fake conntrack entry, in theory, it
 * never runs */
static void
ip_tproxy_fake_timeout(unsigned long null_ptr)
{
	printk("IP_TPROXY: Fake timeout called!");
}
	
static struct nf_hook_ops ip_tproxy_pre_ops = 
{ { NULL, NULL }, ip_tproxy_fn, PF_INET, NF_IP_PRE_ROUTING,
  -130 };

static struct nf_hook_ops ip_tproxy_post_ops = 
{ { NULL, NULL }, ip_tproxy_fn, PF_INET, NF_IP_POST_ROUTING,
  -130 };

static struct nf_hook_ops ip_tproxy_local_out_ops = 
{ { NULL, NULL }, ip_tproxy_fn, PF_INET, NF_IP_LOCAL_OUT,
  -130 };
  
static struct nf_sockopt_ops ip_tproxy_sockopts = 
{ { NULL, NULL }, PF_INET, 
    IP_TPROXY, IP_TPROXY+1, ip_tproxy_setsockopt,
    IP_TPROXY, IP_TPROXY+1, ip_tproxy_getsockopt, 
    0, NULL };

/* init or cleanup the tproxy module */
static int 
init_or_cleanup(int startup)
{
	int ret = 0;
	int i;
	struct proc_dir_entry *proc;

	if (!startup) {
		goto clean_all;
	}

	/* use our own fake conntrack entry, which indicates that packet was
	   tproxied, this let's us use the same -m tproxy match in our filter
	   rules.  The original idea of using a fake conntrack entry to avoid
	   conntracking is by Jozsef Kadlecsik */

        atomic_set(&ip_tproxy_fake_ct.ct_general.use, 1);
        /* ip_tproxy_fake_ct.tuplehash[IP_CT_DIR_ORIGINAL].list.next = (struct list_head *)&ip_tproxy_fake_ct; */
        set_bit(IPS_CONFIRMED_BIT, &ip_tproxy_fake_ct.status);
        ip_tproxy_fake_ct.timeout.function = ip_tproxy_fake_timeout;
        ip_tproxy_fake_ct.infos[IP_CT_NEW].master = &ip_tproxy_fake_ct.ct_general;
        ip_tproxy_fake_ct.nat.info.initialized = (1 << IP_NAT_MANIP_SRC) |
						 (1 << IP_NAT_MANIP_DST);
        ip_tproxy_fake_ct.status |= IPS_TPROXY;

	ip_tproxy_sockref_table = kmem_cache_create("ip_tproxy", sizeof(struct ip_tproxy_sockref), 0,
						    SLAB_HWCACHE_ALIGN, NULL, NULL);
	
	if (!ip_tproxy_sockref_table) {
		ret = -ENOMEM;
		goto clean_nothing;
	}
	
	if (hashsize)
		ip_tproxy_htable_size = hashsize;
	else
		ip_tproxy_htable_size = 127;
	
	ip_tproxy_bylocal = (struct list_head *) vmalloc(sizeof(struct list_head) *
							 ip_tproxy_htable_size * 2);
	if (!ip_tproxy_bylocal) {
		ret = -ENOMEM;
		goto clean_sockref_table;
	}
	ip_tproxy_byforeign = (struct list_head *) ip_tproxy_bylocal + ip_tproxy_htable_size;

	for (i = 0; i < ip_tproxy_htable_size; i++) {
		INIT_LIST_HEAD(&ip_tproxy_bylocal[i]);
		INIT_LIST_HEAD(&ip_tproxy_byforeign[i]);
	}

	proc = proc_net_create("tproxy", 0, NULL);
	if (!proc) goto clean_sockref_hash;
	proc->proc_fops = &ip_tproxy_file_ops;
		                        
	ret = ipt_register_table(&tproxy_table);
	if (ret < 0) {
		printk("IP_TPROXY: can't register tproxy table.\n");
		goto clean_proc;
	}
	
	ret = nf_register_hook(&ip_tproxy_local_out_ops);
	if (ret < 0) {
		printk("IP_TPROXY: can't register local out hook.\n");
		goto clean_table;
	}

	ret = nf_register_hook(&ip_tproxy_post_ops);
	if (ret < 0) {
		printk("IP_TPROXY: can't register postrouting hook.\n");
		goto clean_loops;
	}

	ret = nf_register_hook(&ip_tproxy_pre_ops);
	if (ret < 0) {
		printk("IP_TPROXY: can't register prerouting hook.\n");
		goto clean_postops;
	}

	nf_register_sockopt(&ip_tproxy_sockopts);

	ip_tproxy_udp_unhashed = ip_tproxy_close;
	ip_tproxy_tcp_unhashed = ip_tproxy_close;

	/* initialize confirm and destroy callbacks */
	ip_conntrack_confirmed = ip_tproxy_confirmed;
	ip_conntrack_destroyed_old = ip_conntrack_destroyed;
	ip_conntrack_destroyed = ip_tproxy_conntrack_destroyed;

	printk("IP_TPROXY: Transparent proxy support initialized 2.0.6\n"
	       "IP_TPROXY: Copyright (c) 2002-2007 BalaBit IT Ltd.\n");
	return ret;
 clean_all:

	nf_unregister_sockopt(&ip_tproxy_sockopts);

	ip_conntrack_destroyed = ip_conntrack_destroyed_old;
	ip_conntrack_confirmed = NULL;

 	ip_tproxy_udp_unhashed = NULL;
	ip_tproxy_tcp_unhashed = NULL;

	nf_unregister_hook(&ip_tproxy_pre_ops);

 clean_postops:
	nf_unregister_hook(&ip_tproxy_post_ops);

 clean_loops:
	nf_unregister_hook(&ip_tproxy_local_out_ops);

 clean_table:
	ipt_unregister_table(&tproxy_table);

 clean_proc:
	proc_net_remove("tproxy");

 clean_sockref_hash:
	ip_tproxy_sockref_table_free();
        vfree(ip_tproxy_bylocal);
 	
 clean_sockref_table:
 	kmem_cache_destroy(ip_tproxy_sockref_table);
 	
 clean_nothing:
	return ret;
}

static int __init init(void)
{
	return init_or_cleanup(1);
}

static void __exit fini(void)
{
	init_or_cleanup(0);
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Balázs Scheidler <bazsi@balabit.hu>");
MODULE_DESCRIPTION("Netfilter transparent proxy core module.");

