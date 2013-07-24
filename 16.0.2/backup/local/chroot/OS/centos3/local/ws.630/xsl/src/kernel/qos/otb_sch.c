/* =======================================================================
 *  File    : otb_sch.c
 *  Purpose : otb_sch qdisc APIs and structure
 *  Version : 1.0.0
 * =======================================================================
 *  By : Somech Ovad
 * =======================================================================
 *  Copyright :
 *     This source file is copyright (c) to Expand Networks Ltd.
 * =======================================================================
 */
#include <linux/config.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/notifier.h>
#include <net/ip.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/compiler.h>
#include <net/sock.h>
#include <net/pkt_sched.h>
#include <linux/rbtree.h>
#include "shared/qos.h"
#include "shared/qoscfg.h"
#include "scache.h"
#include "ipv4_utils.h"
#include "shared/xsl_sock.h"
#include "log.h"
#include "global_qdisc.h"
#include "sch_eprio.h"
#include "stats/stats_conntrack.h"
#include "psd/psdconfig.h"

extern atomic_t global_packet_number ;
extern atomic_t global_packet_dropped ;

#define UNIT_NAME "otb_sched:"

#if AOM_OTB_SCH_DEBUG

 #define OTB_DEBUG  1
 #define DPRINTK     printk
 #define OTB_RATECM 1 /* whether to use rate computer */


#else

 #define DPRINTK(format,args ...) 

#endif

#include "otb_sch.h" /* should enjoy the above define */

#define UPDATE_MAX_QUEUE_USAGE(qlen,q)  \
if ( (qlen) > (q)->exstats.max_qlen) { (q)->exstats.max_qlen = qlen; }


/**********************************************************************/
/*  CB usage of the skb :                                             */
/*  unsigned long - for marking the arrival time of the packet;       */
/*  unsigned long - for coding a special message for otb_sch          */

//#define SKB_ARRIVAL_TIME(skb) (*(unsigned long*)(skb)->cb)
//#define SKB_OTB_SCH_CODE(skb) (*((unsigned long*)(skb)->cb + 1))

/**********************************************************************/ 

#define TC_OTB_NUMMODE 		4
#define OTB_EWMAC 2	/* rate average over OTB_EWMAC*OTB_HSIZE sec */
#define OTB_QLOCK(S) spin_lock_bh(&(S)->dev->queue_lock)
#define OTB_QUNLOCK(S) spin_unlock_bh(&(S)->dev->queue_lock)
#define OTB_VER 0x30007	/* major must be matched with number suplied by TC as version */

#if 0 //Ovad
// Ovad shoyld be Defined with control plain
#if OTB_VER >> 16 != TC_OTB_PROTOVER
#error "Mismatched sch_otb.c and pkt_sch.h"
#endif
#endif //Ovad

#define TS_GE(a,b) (a - b < 0x80000000)
#define OTB_Q_READY(cl) ((cl->ctype == OTB_LEAF)? (cl->un.leaf.q->q.qlen) : (INNER_Q(cl)->send_status != OTB_IDLE))
#define OTB_IN_WQ(cl) ((cl->cmode != OTB_GREEN) || ((cl->ctype == OTB_INNER) && INNER_Q(cl)->waits_for_events))
#define OTB_IN_SQ(cl) ((cl->cmode != OTB_RED) && OTB_Q_READY(cl))

/* debugging support; S is subsystem, these are defined:
  0 - netlink messages
  1 - enqueue
  2 - drop & requeue
  3 - dequeue main
  4 - dequeue one prio DRR part
  5 - dequeue class accounting
  6 - class overlimit status computation
  7 - hint tree
  8 - event queue
 10 - rate estimator
 11 - classifier 
 12 - fast dequeue cache

 L is level; 0 = none, 1 = basic info, 2 = detailed, 3 = full
 q->debug uint32 contains 16 2-bit fields one for subsystem starting
 from LSB
 */
#ifdef OTB_DEBUG
#define OTB_DBG(S,L,FMT,ARG...) if (((q->debug>>(2*S))&3) >= L) \
	printk(KERN_DEBUG FMT,##ARG)
#define OTB_CHCL(cl) BUG_TRAP((cl)->magic == OTB_CMAGIC)
#define OTB_PASSQ q,
#define OTB_ARGQ struct otb_sched *q,
#define static
#define __inline__
#define inline
#define OTB_CMAGIC 0xFEFAFEF1
#define otb_safe_rb_erase(N,R) do { BUG_TRAP((N)->rb_color != -1); \
		if ((N)->rb_color == -1) break; \
		rb_erase(N,R); \
		(N)->rb_color = -1; } while (0)
int seldom_counter = 0;
#define SELDOM_PRINT(FMT, ARG...) do{ seldom_counter++; \
	if(!(seldom_counter & 0xFF)) { \
	seldom_counter = 0; \
	printk(FMT,##ARG); } } while(0)    
unsigned long burst_inner_cnt = 21;
unsigned long burst_seldom_cnt = 0xF;
#define BURST_PRINT(FMT, ARG...) do {\
	if(!(burst_seldom_cnt & 0xFF)) {burst_inner_cnt = 0; \
									 printk("-----------------------------\n");}\
	burst_seldom_cnt++;\
	if(burst_inner_cnt < 20) {printk(FMT,##ARG); burst_inner_cnt++;} } while (0)
#else
#define OTB_DBG(S,L,FMT,ARG...)
#define OTB_PASSQ
#define OTB_ARGQ
#define OTB_CHCL(cl)
//#define otb_safe_rb_erase(N,R) rb_erase(N,R)
#define SELDOM_PRINT(counter, FMT, ARG...)
//#define otb_safe_rb_erase(N,R) do { rb_erase((N),(R)); (N)->rb_color = -1; } while (0)
#define otb_safe_rb_erase(N,R) do { BUG_TRAP((N)->rb_color != -1); \
		if ((N)->rb_color == -1) break; \
		rb_erase(N,R); \
		(N)->rb_color = -1; } while (0)
#define BURST_PRINT(counter, FMT, ARG...)
#endif

#define INNER_Q(cl) ((struct otb_sched*)(cl->un.inner.q->data))

#define AVERAGE_COMPRESSION_RATE 4

// power bonus according to the class mode
static unsigned long modeBonus[] = {
	0,		// OTB_RED   
	0,		// OTB_ORANGE
	HZ*20,	// OTB_YELLOW
	HZ*30	// OTB_GREEN 
};

static short hysteresis_enabled = 0;

static void update_peer_priority_data(struct otb_class * cl,struct aom_otb_glob *hopt,unsigned int flag);
static void update_wan_priority_weights (struct otb_class * peer_cl, struct otb_class * wan_cl,unsigned int flag);
static void update_rule_priority_params(struct otb_class *rule_cl , struct otb_class * peer_cl, int log_flag);
static void update_peer_rules_priority_params(struct otb_class *  peer_cl, int log_flag);



//#define MAX_USAGE 0xFFFFFFFF
#define MAX_USAGE (~0UL)
/* TODO: maybe compute rate when size is too large .. or drop ? */
static __inline__ long L2T(struct otb_class *cl,struct qdisc_rate_table *rate,
	int size)
{ 
    int slot;

	cl->usage += size;
	slot = cl->usage >> rate->rate.cell_log;
	cl->usage &= ~(MAX_USAGE << rate->rate.cell_log);
    if (slot > 255) {
	cl->xstats.giants++;
	slot = 255;
    }
    return rate->data[slot];
}
#undef MAX_USAGE


/* compute hash of size OTB_HSIZE for given handle */
static __inline__ int otb_hash(u32 h) 
{
#if OTB_HSIZE != 16
 #error "Declare new hash for your OTB_HSIZE"
#endif
    h ^= h>>8;	/* stolen from cbq_hash */
    h ^= h>>4;
    return h & 0xf;
}

/* find class in global hash table using given handle */
static __inline__ struct otb_class *otb_find(u32 handle, struct Qdisc *sch)
{
	struct otb_sched *q = (struct otb_sched *)sch->data;
	struct list_head *p;
	if (TC_H_MAJ(handle) != sch->handle) 
		return NULL;

	/* if we are in wan and have root and classid match*/
	if ( (q->ctype == OTB_INNER) && q->root && (TC_H_MIN(handle) == AOM_QOS_WAN_PEERS_ID) )
		return q->root;
	/* search the class in the hash */
	list_for_each (p,q->hash+otb_hash(handle)) {
		struct otb_class *cl = list_entry(p,struct otb_class,hlist);
		if (cl->classid == handle) {
			DPRINTK("otb_find found the class\n");
			return cl;
		}
	}
	return NULL;
}


/* 
 * What		: resolve the target class based on the realm number (represents a peer)
 * Args		: skb = target packet ; sch = father qdisc
 * Return	: destination address
 */
static struct  otb_class *otb_inner_classify(struct sk_buff *skb, struct Qdisc *sch)
{
	struct otb_class *cl = NULL;
        u32 realm = 0 ;
	DPRINTK("otb_inner_classify\n");
	if (skb->dst) {
	        realm = skb->dst->tclassid;         
		u32 classid = 0;
		AOM_QOS_RES_PEER_CLASS_ID(realm,classid);
		cl = otb_find(classid,sch);
	}
	return cl;
}

/* 
 * What		: resolve the target class by exemine the filter list.
 * It returns NULL if the packet should be dropped or -1 if the packet
 * should be passed directly thru. In all other cases leaf class is returned.
 * We allow direct class selection by classid in priority. The we examine
 * filters in qdisc and in inner nodes (if higher filter points to the inner
 * node). If we end up with classid MAJOR:0 we enqueue the skb into special
 * internal fifo (direct). These packets then go directly thru. If we still 
 * have no valid leaf we try to use MAJOR:default leaf. It still unsuccessfull
 * then finish and return direct queue.
 * Args		: skb = target packet ; sch = father qdisc
 * Return	: destination address
 */


static struct otb_class *otb_leaf_classify(struct sk_buff *skb, struct Qdisc *sch)
{
	struct otb_sched *q = (struct otb_sched *)sch->data;
	struct otb_class *cl = NULL;
	struct tcf_result res;
	DPRINTK("otb_leaf_classify sch 0x%x skb %p expand_info %p\n",
		sch->handle,skb,skb->expand_info);
  
	if (tc_classify(skb,q->filter_list, &res)>= 0) {
		/*matching is found*/
		if((cl = (struct otb_class*)res.class) == NULL)
			cl = otb_find(res.classid,sch);
	}
	// else
	//  No matching : keep NULL assignment
	return cl;
}

/* 
 * What		: committ classification per session by using session cache in 
                  order to check whether to call otb_classify,or to retrieve
                  otb_class address from session cache,and return it.
 * Args		: skb = target packet ; sch = father qdisc
 * Return	: destination address
 */
static struct otb_class*  otb_session_classify(struct sk_buff *skb, struct Qdisc *sch)
{
	struct session_cache_info * sc ;
	struct otb_sched *q = (struct otb_sched *)sch->data;
	enum session_cache_status cache_status ;
	struct otb_class * cl = NULL;
	DPRINTK("otb_session_classify: sch 0x%x skb %p\n",
		sch->handle,skb);
	unsigned char scache_entry ;
	sc  = session_cache_get(skb,&cache_status);
   
	if (!sc) {
		/* session is not found in the connection tracking table*/ 
		DPRINTK("otb_session_classify no sc entry call leaf classify\n");
		cl = otb_leaf_classify(skb,sch);
		return(cl);
	} 
  
	/* scache entries index are shifted by one because scache version is in entry 0 */  
	scache_entry = q->direction +1 ;
  
	if (cache_status == MATCHING_ENTRY_FOUND) {
 
		cl = (struct otb_class*)sc->session_data.data_arr[scache_entry];
		if(!cl) {
			cl = otb_leaf_classify(skb,sch);
			sc->session_data.data_arr[scache_entry]=(unsigned long)cl;
			if (cl == NULL)
				DPRINTK("committ classification : classid is NULL\n\n");
			else
				DPRINTK("committ classification class id is 0x%x\n" ,cl->classid);
		} else {
			/* found class in session cache */
			if((TC_H_MAJ(cl->classid)) != (TC_H_MAJ(sch->handle))) {
				/* Class caching is wrong : committ classification */ 
				cl = otb_leaf_classify(skb,sch);
				sc->session_data.data_arr[scache_entry]=0;
			}
		}
	} else {
		if(cache_status == NEW_ALLOCATED_ENTRY) {
			DPRINTK(" Error : entry must be pre allocated in global\n");   
			cl = otb_leaf_classify(skb,sch);
			sc->session_data.data_arr[scache_entry]=(unsigned long)cl;
		}
	} 
	return cl ;
}




#ifdef OTB_DEBUG
static void otb_next_rb_node(rb_node_t **n);
#define OTB_DUMTREE(root,memb) if(root) { \
	rb_node_t *n = (root)->rb_node; \
	while (n->rb_left) n = n->rb_left; \
	while (n) { \
		struct otb_class *cl = rb_entry(n, struct otb_class, memb); \
		DPRINTK(" %x(m:%d,p:%lud)",cl->classid, cl->cmode, cl->power); otb_next_rb_node (&n); \
	} }

static void otb_debug_dump (struct otb_sched *q)
{
	int i;
	DPRINTK(KERN_DEBUG "otb*g j=%lu, mode %d, power %lu. Heap:\n",
			jiffies,(q->root?q->root->cmode:-1),(q->root?q->root->power:-1));
	/* heep */
	if(q->send_pq.rb_node)
		OTB_DUMTREE(&q->send_pq, send_node);
	DPRINTK("\nClasses :\n");
	/* classes */
	for (i = 0; i < OTB_HSIZE; i++) {
		struct list_head *l;
		list_for_each (l,q->hash+i) {
			struct otb_class *cl = list_entry(l,struct otb_class,hlist);
			//long diff = PSCHED_TDIFF_SAFE(q->  int count = 0;now, cl->t_c, (u32)cl->mbuffer, 0);
			DPRINTK(KERN_DEBUG "otb*c%x m=%d p=%ld\n",
					cl->classid,cl->cmode,cl->power);
		}
	}
}
#endif

/**
 * otb_add_to_send_tree - adds class to the send queue
 */
static void otb_add_to_send_tree (struct otb_sched *q,
		struct otb_class *cl, int debug_hint)
{
  rb_node_t **p = &q->send_pq.rb_node, *parent = NULL;
  unsigned long arrival_time = jiffies;/* just for initialization */ 
  struct otb_sched * inner_qdisc; 
  
  OTB_DBG(7,3,"otb_add_send cl=%X key=%lu\n",cl->classid,cl->power);
#ifdef OTB_DEBUG
  if (cl->send_node.rb_color != -1) { BUG_TRAP(0); return; }
  OTB_CHCL(cl);
#endif
  if(cl->ctype == OTB_LEAF) {
    if(cl->arrival_time)
      arrival_time = cl->arrival_time;
    /* Determine leaf class power */
    
    cl->power =  arrival_time - ( modeBonus[cl->cmode]+ cl->prio_bonus);
    
  
  } else {
    /* Inner class power */
    //cl->power = INNER_Q(cl)->power_cache;
    inner_qdisc = INNER_Q(cl);
    cl->power = inner_qdisc->power_cache.arrival_time - (modeBonus[inner_qdisc->power_cache.cmode] + cl->wan_prio_bonus[inner_qdisc->power_cache.prio]); 
  }
/* 	BURST_PRINT("adding to send: cl 0x%X type %d power %ld qlen %d mode %d arrival %lu\n", */
/* 		
		cl->classid,cl->ctype, (long)cl->power, (cl->ctype == OTB_LEAF)?cl->un.leaf.q.qlen:cl->un.inner.q->q.qlen, cl->cmode, arrival_time); */


/* determine power cache */
  if (TS_GE(q->power_cache.power, cl->power) || (q->send_status == OTB_IDLE)){
    q->power_cache.power = cl->power;
    if(cl->ctype == OTB_LEAF){ 
      q->power_cache.arrival_time = arrival_time;
      q->power_cache.prio = cl->prio;
      q->power_cache.cmode = cl->cmode;
    }
  }

  while (*p) {
    struct otb_class *c; parent = *p;
    c = rb_entry(parent, struct otb_class, send_node);
    if (TS_GE(cl->power, c->power))
      p = &parent->rb_right;
    else 
      p = &parent->rb_left;
  }

  rb_link_node(&cl->send_node, parent, p);
  rb_insert_color(&cl->send_node, &q->send_pq);

  if((q->send_status != OTB_READY) && (q->root?(q->root->cmode != OTB_RED):1)){
    if(cl->cmode == OTB_ORANGE)
      q->send_status = OTB_EXCEED;
    else
      q->send_status = OTB_READY;
  }
}



/**
 * otb_add_to_wait_tree - adds class to the event queue with delay
 *
 * The class is added to priority event queue to indicate that class will
 * change its mode in cl->pq_key microseconds. Make sure that class is not
 * already in the queue.
 */
static void otb_add_to_wait_tree (struct otb_sched *q, struct otb_class *cl, long delay)
{
	rb_node_t **p = &q->wait_pq.rb_node, *parent = NULL;
	OTB_DBG(7,3,"otb_add_wt cl=%X key=%lu\n",cl->classid,cl->pq_key);
#ifdef OTB_DEBUG
	if (cl->pq_node.rb_color != -1) { BUG_TRAP(0); return; }
	OTB_CHCL(cl);
#endif

	cl->pq_key = jiffies + PSCHED_US2JIFFIE(delay);
	if (cl->pq_key == jiffies)
		cl->pq_key++;
	if( (cl->ctype == OTB_INNER) && (INNER_Q(cl)->waits_for_events) &&
		((TS_GE(cl->pq_key, INNER_Q(cl)->near_ev_cache)) || (cl->cmode == OTB_GREEN)) )
		cl->pq_key = INNER_Q(cl)->near_ev_cache;
/* 	BURST_PRINT("adding to wait: cl %p mode %d delay %ld key %lu\n", */
/* 				cl, cl->cmode, delay, cl->pq_key); */
	/* update the nearest event cache */
	if (TS_GE(q->near_ev_cache, cl->pq_key))
		q->near_ev_cache = cl->pq_key;
	while (*p) {
		struct otb_class *c; parent = *p;
		c = rb_entry(parent, struct otb_class, pq_node);
		if (TS_GE(cl->pq_key, c->pq_key))
			p = &parent->rb_right;
		else 
			p = &parent->rb_left;
	}
	
	rb_link_node(&cl->pq_node, parent, p);	
	rb_insert_color(&cl->pq_node, &q->wait_pq);
	q->waits_for_events = 1;
}

/**
 * otb_next_rb_node - finds next node in binary tree
 *
 * When we are past last key we return NULL.
 * Average complexity is 2 steps per call.
 */
static void otb_next_rb_node(rb_node_t **n)
{
  rb_node_t *p;
  if ((*n)->rb_right) {
    *n = (*n)->rb_right;
    while ((*n)->rb_left) 
      *n = (*n)->rb_left;
    return;
  }
  while ((p = (*n)->rb_parent) != NULL) {
    if (p->rb_left == *n) break;
    *n = p;
  }
  *n = p;
}

static __inline__ void otb_update_send_info(struct otb_sched* q)
{
	struct otb_class *cl;
	if(q->root?(q->root->cmode != OTB_RED):1) {
		if(q->direct_queue.qlen) {
			q->power_cache.power = jiffies - get_default_passthrough_bonus();
			q->send_status = OTB_READY;
		} else {
			rb_node_t *p = q->send_pq.rb_node;
			if (p) {
				while (p->rb_left) p = p->rb_left;	
				cl = rb_entry(p, struct otb_class, send_node);
				q->power_cache.power = cl->power;
				if(cl->ctype == OTB_LEAF) {
					q->power_cache.arrival_time = cl->arrival_time;
					q->power_cache.prio = cl->prio;
					q->power_cache.cmode = cl->cmode;
				} 
				if(cl->cmode == OTB_ORANGE)
					q->send_status = OTB_EXCEED;
				else
					q->send_status = OTB_READY;
			} else
				q->send_status = OTB_IDLE;
		}
	} else
		q->send_status = OTB_IDLE;
} 

/**
 * otb_class_mode - computes and returns current class mode
 *
 * It computes cl's mode at time cl->t_c+diff and returns it. If mode
 * is not OTB_GREEN then cl->pq_key is updated to time difference
 * from now to time when cl will change its state. 
 * Also it is worth to note that class mode doesn't change simply
 * at cl->{c,}tokens == 0 but there can rather be hysteresis of 
 * 0 .. -cl->{c,}buffer range. It is meant to limit number of
 * mode transitions per time unit. The speed gain is about 1/6.
 */
static __inline__ enum otb_cmode 
otb_class_mode(struct otb_class *cl,long *diff)
{
	long toks, ctoks_min_limit, toks_max_limit;
	ctoks_min_limit = (hysteresis_enabled && 
					  (cl->cmode != OTB_RED) && (cl->cmode != OTB_ORANGE) ) ?
					  -cl->cbuffer : 0;

	if ((toks = (cl->ctokens + *diff)) < ctoks_min_limit) {
		*diff = -toks;
		if(cl->exceed)	   
			return OTB_ORANGE;
		else
			return OTB_RED;
	}
	toks_max_limit = (hysteresis_enabled && (cl->cmode == OTB_GREEN) ) ? -cl->buffer : 0;
    if ((toks = (cl->tokens + *diff)) >= toks_max_limit)
		return OTB_GREEN;

	*diff = -toks;
	return OTB_YELLOW;
}



static int otb_enqueue_fragment(struct sk_buff   *skb,
				struct Qdisc     *sch, 
				struct otb_class *cl)
{
  struct sk_buff *  skb_p = NULL , *next_skb = NULL; 
  struct sk_buff * skb_list = NULL;
   unsigned int update_events = 0;
  struct otb_sched *q = (struct otb_sched *)sch->data;
  //unsigned long cached_arrival_tag =  SKB_ARRIVAL_TIME(skb);
  unsigned long cached_arrival_tag =  SKB_GET_EXPAND_INFO_PARAM(skb, skb_arrival_time, EXPAND_TYPE_VAL);
   unsigned int skb_len = skb->len ;
   struct stats_conntrack_aggregate* ct_stats = NULL;
  
  struct iphdr *iph = skb->nh.iph;
  unsigned int datalink_len = skb->nh.raw - skb->data;
  unsigned int hlen = iph->ihl * 4;
  unsigned int left = skb->len - hlen - datalink_len;        /* Space per frame */
  unsigned int len = q->fragmentation - hlen - datalink_len; /* Size of data space */
  int fragments_count = (left/len) + 1;
  DPRINTK("otb_enqueue_fragment was called\n");
  /* check if after fragmentation there will be enough space in the queue */
  DPRINTK("fragments count is %d\n",fragments_count);
  if(cl->un.leaf.q->q.qlen + fragments_count > cl->max_qlen){
    DPRINTK("otb_enqeue_fragment - full\n");

  #if STATS_CONNTRACK_FLAG
  ct_stats = stats_conntrack_get(skb);
  if(ct_stats){
       ct_stats->dropped.dir[cl->direction].bytes += skb_len;
       ct_stats->dropped.dir[cl->direction].packets ++; 
      }
  #endif
  
    sch->stats.drops++;
    cl->stats.drops++;
    kfree_skb(skb);
    return NET_XMIT_DROP;
  }  
  /* fragment the packet */
  if(m_ip_fragment( skb , &skb_list , q->fragmentation ) ){
    /* frag failed and took care for freeing the skb */
    DPRINTK("fragmentation failed\n");

  #if STATS_CONNTRACK_FLAG
    ct_stats = stats_conntrack_get(skb);
    if(ct_stats){
       ct_stats->dropped.dir[cl->direction].bytes += skb_len;
       ct_stats->dropped.dir[cl->direction].packets ++; 
      }     
   #endif
  
    sch->stats.drops++;
    cl->stats.drops++;
    return NET_XMIT_DROP;
  }
   
  skb_p = skb_list;
  /* cache the whether this should be the first packet in no red state */
  if((cl->un.leaf.q->q.qlen == 0) && (cl->cmode != OTB_RED))
   update_events = 1;
  /* go over the fragmented skb list */ 
  while(skb_p){
    next_skb = skb_p->next;
    skb_p->next = NULL ;
    /* insert to class private list, with origin arrival time */
    //SKB_ARRIVAL_TIME(skb_p) = cached_arrival_tag;
    SKB_SET_EXPAND_INFO_PARAM_VAL(skb_p, skb_arrival_time, cached_arrival_tag);
	if (cl->un.leaf.q->ops->enqueue(skb_p, cl->un.leaf.q) != NET_XMIT_SUCCESS) {
		sch->stats.drops++;
		cl->stats.drops++;
		return NET_XMIT_DROP;
	}
	if ( cl->un.leaf.q->q.qlen > cl->exstats.max_qlen) {
			cl->exstats.max_qlen = cl->un.leaf.q->q.qlen;
	}
    /* update class and qdisc stats */
    cl->stats.packets++; 
    cl->stats.bytes += skb_p->len;
	cl->exstats.frag++;
	q->exstats.frag++;
	q->parent_class->parent_qdisc->exstats.frag++;
    sch->q.qlen++; 
	UPDATE_MAX_QUEUE_USAGE(sch->q.qlen,q);
    sch->stats.packets++;
	
    sch->stats.bytes += skb_p->len;
    /* increment to next member */
    skb_p = next_skb;
  }
  /* update events heap based on cached flag */
  if (update_events)
    otb_add_to_send_tree(q,cl,1);
  /* return internal code for upper layer stats updates */
  return NET_XMIT_SUCCESS_FRAG;  /*instead of just NET_XMIT_SUCCESS*/
}




/**
 * otb_change_class_mode - changes classe's mode
 *
 * This should be the only way how to change classe's mode under normal
 * cirsumstances. Routine will update feed lists linkage, change mode
 * and add class to the wait event queue if appropriate. New mode should
 * be different from old one and cl->pq_key has to be valid if changing
 * to mode other than OTB_GREEN (see otb_add_to_wait_tree).
 */
static void 
otb_change_class_mode(struct otb_sched *q, struct otb_class *cl, long *diff, int was_in_sq)
{ 
	OTB_CHCL(cl);
	cl->cmode = otb_class_mode(cl,diff);
	if(cl == q->root) {
		otb_update_send_info(q);
		return;	
	} 
	if(was_in_sq)
		otb_safe_rb_erase(&cl->send_node,&q->send_pq);
	if (OTB_IN_SQ(cl))
		otb_add_to_send_tree(q, cl, 1);
}

/* 
   Note : PASSTHROUGH packets are routed into the direct queue
   although their filter points at a dedicated shaper/class.
   TOS marking is availble for this kind of packets hence
   it is done in the enqueue and not on the dequeue for all other
   types of priority   
*/ 
static int otb_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
    struct otb_sched *q = (struct otb_sched *)sch->data;
    struct otb_class *cl = NULL;
    struct stats_conntrack_aggregate* ct_stats = NULL;
	
    int  ret_val = NET_XMIT_SUCCESS;
    __u32 enqueued_packets = 1 ,
          enqueued_bytes = skb->len;

    DPRINTK("otb_enqueue was called\n");
    if( q->ctype == OTB_INNER ) { /* acts for shaping wan */
		//SKB_ARRIVAL_TIME(skb) = jiffies;
                SKB_SET_EXPAND_INFO_PARAM_VAL(skb, skb_arrival_time, jiffies);
		/* find class according to realm */
		cl = otb_inner_classify(skb,sch);
    } else {
		/* acts as peer, need to use per session filters */
		cl = otb_session_classify(skb,sch);
    }

    /* Error with classification :                                */
    /* realm was not configured properly, no class matched , bug  */
    if (!cl) {
		/* for now go to direct */
		DPRINTK("otb_enqueue - FATAL ERROR\n");
		if (q->direct_queue.qlen < q->max_qlen) {
			/* enqueue */
			__skb_queue_tail(&q->direct_queue, skb);
			q->direct_pkts++;
			q->power_cache.power = jiffies - get_default_passthrough_bonus();
			if(q->root?(q->root->cmode != OTB_RED):1)
				q->send_status = OTB_READY;
			sch->q.qlen += enqueued_packets;
			UPDATE_MAX_QUEUE_USAGE(sch->q.qlen,q);
			sch->stats.packets += enqueued_packets;
			sch->stats.bytes += enqueued_bytes;
			return NET_XMIT_SUCCESS;
		} 
      //else {
     
		#if STATS_CONNTRACK_FLAG
		ct_stats = stats_conntrack_get(skb);
		if(ct_stats) {
			ct_stats->dropped.dir[q->direction].bytes += skb->len;
			ct_stats->dropped.dir[q->direction].packets ++; 
		} 
		#endif
    
		kfree_skb (skb);
		sch->stats.drops++;
		/* update the null_clsfy class stats */
		return NET_XMIT_DROP;
    }

      
    /* PASSTHROUGH :                                                                  */
    /* if we are in wan we should not treat this case for now                         */
    /* if we are in a peer and the class has PASSTHROUGH then go to the special queue */
    if ( (q->ctype == OTB_LEAF) && (cl->prio == OTB_PASSTHROUGH) ) {
		/* enqueue to helper queue */
		if (q->direct_queue.qlen < q->max_qlen) {
			/* update its virtual class shaper stats */
			cl->stats.packets++;
			cl->stats.bytes += skb->len;
			/* packet tos marking is done here as later I don't know which ones from the passthrough */
			/* classes were configured to tos mark the packets                                       */
			if ( cl->mark_tos ) 
				m_ip_mark_tos(skb,cl->tos_value,cl->tos_mask);
			/* enqueue */
			__skb_queue_tail(&q->direct_queue, skb);
			q->direct_pkts++;
			q->power_cache.power = jiffies - get_default_passthrough_bonus();
			if(q->root?(q->root->cmode != OTB_RED):1)
				q->send_status = OTB_READY;
		} else {

			#if STATS_CONNTRACK_FLAG
			ct_stats = stats_conntrack_get(skb);
			if(ct_stats) {
				ct_stats->dropped.dir[q->direction].bytes += skb->len;
				ct_stats->dropped.dir[q->direction].packets ++; 
			}
			#endif
     
			kfree_skb (skb);
			sch->stats.drops++;
			cl->stats.drops++;
			return NET_XMIT_DROP;
		}
    } /* end case of PASSTHROUGH */
    
	else if (((cl->ctype == OTB_LEAF)&&(cl->un.leaf.q->q.qlen >=cl->max_qlen))||(cl->prio == OTB_BLOCK)) {
		if (cl->prio == OTB_BLOCK) {

			#if STATS_CONNTRACK_FLAG
			ct_stats = stats_conntrack_get(skb);
			if(ct_stats) {
				ct_stats->discard.dir[q->direction].bytes += skb->len;
				ct_stats->discard.dir[q->direction].packets ++; 
			}
			#endif
     
			/* update stats for rule class */
			cl->exstats.discarded++;
			/* update peer block statistics */
			q->exstats.discarded++;
			/* should tell upper layer that packet wasn't just dropped */
			kfree_skb (skb);
			return NET_XMIT_POLICED;
		
		} else {

			#if STATS_CONNTRACK_FLAG
			ct_stats = stats_conntrack_get(skb);
			if(ct_stats) {
				ct_stats->dropped.dir[q->direction].bytes += skb->len;
				ct_stats->dropped.dir[q->direction].packets ++; 
			}
			#endif
        
			sch->stats.drops++;
			cl->stats.drops++;
			kfree_skb (skb);
			return NET_XMIT_DROP;
		}  
	} else {
		if(cl->ctype == OTB_LEAF) {
			struct Qdisc *lfq = cl->un.leaf.q;
			/*********************/
			/*   Fragmentation   */
			/*********************/
			CB_MTU_SET(skb, 0); 
			if ( q->fragmentation && 
				 (cl->prio >= OTB_LOW) && (cl->prio <= OTB_HIGH) &&
				 (skb->len > q->fragmentation) ) {
				/* NOTE: The following function updates statistics 
						 and send heap */
				return otb_enqueue_fragment(skb,sch,cl);
			}
			/* enqueue to leaf qdisc */
			if ((ret_val = lfq->enqueue(skb, lfq)) != NET_XMIT_SUCCESS) {
				sch->stats.drops++;
				cl->stats.drops++;
				return ret_val;
			}
			if (lfq->q.qlen > cl->exstats.max_qlen)
				cl->exstats.max_qlen = lfq->q.qlen;

			if((lfq->q.qlen == 1) && (cl->cmode != OTB_RED))
				otb_add_to_send_tree(q,cl,1);
		} else {
			enum otb_send_status old_send_status = INNER_Q(cl)->send_status;
			struct Qdisc *iq = cl->un.inner.q;
			/* cache bytes and packets before enqueue due to possible fragmentation */
			__u64 cached_bytes = iq->stats.bytes;
			__u32 cached_packets = iq->stats.packets;
			/* enqueue packet to peer */
			ret_val = iq->enqueue(skb, iq);
			/* check enqueue result */
			switch (ret_val) {
			case (NET_XMIT_SUCCESS_FRAG):
				{
					enqueued_packets = iq->stats.packets - cached_packets;
					enqueued_bytes   = iq->stats.bytes - cached_bytes;
					break;
				}
			case (NET_XMIT_SUCCESS):
				{
					break;
				}
			default: /* for example drop / block */
				{
					sch->stats.drops++;
					cl->stats.drops++;
					if (ret_val == NET_XMIT_POLICED) {
						/* update stats for peer class */
						cl->exstats.discarded++;
						/* update wan block statistics */
						q->exstats.discarded++;
						return NET_XMIT_POLICED;	  
					}
					/* Note : upon dropped / discard no increments of bytes and packets */
					return NET_XMIT_DROP;
				}
			};

			/* enqueud passed hence should update send tree */
			if((old_send_status == OTB_IDLE) && (INNER_Q(cl)->send_status != OTB_IDLE) && 
			   (cl->cmode != OTB_RED))
				otb_add_to_send_tree(q,cl,1);
		}
		cl->stats.packets += enqueued_packets;
		cl->stats.bytes += enqueued_bytes;
	}
    /*******************************************************
      Note : any updates here should go also in side fragment
			 enqueue function untill proper code is written
    ********************************************************/
    sch->q.qlen += enqueued_packets;
	UPDATE_MAX_QUEUE_USAGE(sch->q.qlen, q);
    sch->stats.packets += enqueued_packets;
    sch->stats.bytes += enqueued_bytes;
    OTB_DBG(1,1,"otb_enq_ok cl=%X skb=%p\n",cl?cl->classid:0,skb);
    return ret_val; /* should always be NET_XMIT_SUCCESS or NET_XMIT_SUCCESS_FRAG */
}

/* TODO: requeuing packet charges it to policers again !! */
static int otb_requeue(struct sk_buff *skb, struct Qdisc *sch)
{
  struct otb_sched *q = (struct otb_sched *)sch->data;
  struct otb_class *cl =NULL;	
  DPRINTK("otb_requeue was called\n");
  if (q->ctype == OTB_INNER) /* acts for shaping wan */
    /* find class according to realm */
    cl = otb_inner_classify(skb,sch);
  else 
    /* acts as peer, need to use per session filters */
    cl = otb_session_classify(skb,sch);

  /* Error with classification :                                */
  /* realm was not configured properly, no class matched , bug  */
  if (!cl) {
    /* for now go to direct - later insert to a special class */
    DPRINTK("otb_enqueue - FATAL ERROR\n");
    if (q->direct_queue.qlen < q->max_qlen) {
      /* enqueue */
      __skb_queue_tail(&q->direct_queue, skb);
      q->direct_pkts++;
      q->power_cache.power = jiffies - get_default_passthrough_bonus();
      if(q->root?(q->root->cmode != OTB_RED):1)
	q->send_status = OTB_READY;
      sch->q.qlen += 1;
	  UPDATE_MAX_QUEUE_USAGE(sch->q.qlen, q);
      sch->stats.packets += 1;
      sch->stats.bytes += skb->len;
      return NET_XMIT_SUCCESS;
    } 
    //else {
    kfree_skb (skb);
    sch->stats.drops++;
    return NET_XMIT_DROP;
  }


  /* PASSTHROUGH case */
  if ( (q->ctype == OTB_LEAF) && (cl->prio == OTB_PASSTHROUGH) ) {
    /* enqueue to helper queue */
    if (q->direct_queue.qlen < q->max_qlen) {
      /* update its virtual class shaper stats */
      cl->stats.packets++;
      cl->stats.bytes += skb->len;
      /* requeue to direct queue */
      __skb_queue_tail(&q->direct_queue, skb);
      q->direct_pkts++;
      q->power_cache.power = jiffies - get_default_passthrough_bonus();
      if(q->root?(q->root->cmode != OTB_RED):1)
	q->send_status = OTB_READY;
    } else {
      kfree_skb (skb);
      sch->stats.drops++;
      cl->stats.drops++;
      return NET_XMIT_DROP;
    }
  } else if (((cl->ctype==OTB_LEAF)?cl->un.leaf.q->q.qlen:cl->un.inner.q->q.qlen) >= q->max_qlen) {
    sch->stats.drops++;
    cl->stats.drops++;
    kfree_skb (skb);
    return NET_XMIT_DROP;
  } else {
    if(cl->ctype == OTB_LEAF) {
      /* no need to check BLOCK as we are in requeue    */
      /* no need for fragmentation as we are in requeue */
      if (cl->un.leaf.q->ops->requeue(skb, cl->un.leaf.q) != NET_XMIT_SUCCESS) {
	sch->stats.drops++;
	cl->stats.drops++;
	return NET_XMIT_DROP;
      } 
      if((cl->un.leaf.q->q.qlen == 1) && (cl->cmode != OTB_RED))
	otb_add_to_send_tree(q,cl,1);
    }	else {
      enum otb_send_status old_send_status = INNER_Q(cl)->send_status;
      if (cl->un.inner.q->ops->requeue(skb, cl->un.inner.q) != NET_XMIT_SUCCESS) {
	sch->stats.drops++;
	cl->stats.drops++;
	return NET_XMIT_DROP;
      } else {
	if((old_send_status == OTB_IDLE) && (INNER_Q(cl)->send_status == OTB_READY) && 
	   (cl->cmode != OTB_RED))
	  otb_add_to_send_tree(q,cl,1);
      }
    }
  }
  sch->q.qlen++;
  UPDATE_MAX_QUEUE_USAGE(sch->q.qlen,q);
  OTB_DBG(1,1,"otb_req_ok cl=%X skb=%p\n",cl?cl->classid:0,skb);
  return NET_XMIT_SUCCESS;
}

static void otb_timer(unsigned long arg)
{
    struct Qdisc *sch = (struct Qdisc*)arg;
    sch->flags &= ~TCQ_F_THROTTLED;
    wmb();
    netif_schedule(sch->dev);
}

#ifdef OTB_RATECM
#define RT_GEN(D,R) R+=D-(R/OTB_EWMAC);D=0
static void otb_rate_timer(unsigned long arg)
{
	struct Qdisc *sch = (struct Qdisc*)arg;
	struct otb_sched *q = (struct otb_sched *)sch->data;
	struct list_head *p;

	/* lock queue so that we can muck with it */
	OTB_QLOCK(sch);
	OTB_DBG(10,1,"otb_rttmr j=%ld\n",jiffies);

	q->rttim.expires = jiffies + HZ;
	add_timer(&q->rttim);

	/* scan and recompute one bucket at time */
	if (++q->recmp_bucket >= OTB_HSIZE) 
		q->recmp_bucket = 0;
	list_for_each (p,q->hash+q->recmp_bucket) {
		struct otb_class *cl = list_entry(p,struct otb_class,hlist);
		OTB_DBG(10,2,"otb_rttmr_cl cl=%X sbyte=%lu spkt=%lu\n",
				cl->classid,cl->sum_bytes,cl->sum_packets);
		RT_GEN (cl->sum_bytes,cl->rate_bytes);
		RT_GEN (cl->sum_packets,cl->rate_packets);
	}
	OTB_QUNLOCK(sch);
}
#endif
                                          
/**
 * otb_charge_class - charges ammount "bytes" to class
 *
 * Routine assumes that packet "bytes" long was dequeued from cl.
 * It accounts bytes to ceil and rate leaky bucket for cl.
 * It also handles possible of mode resulting
 * from the update. Note that mode can also increase here (YELLOW to
 * GREEN) because we can use more precise clock that event queue here.
 * In such case we remove class from event queue first.
 */
static void otb_charge_class(struct otb_sched *q,struct otb_class *cl,int bytes, int was_in_wq, int inSend)
{	
	long toks,diff;
	OTB_DBG(5,1,"otb_chrg_cl cl=%X len=%d\n",cl->classid,bytes);

#define OTB_ACCNT(T,B,R) toks = diff + cl->T; \
	if (toks > cl->B) toks = cl->B; \
    toks -= (L2T(cl, cl->R, abs(bytes)) * (bytes >= 0 ? 1 : -1)); \
	if (toks <= -cl->mbuffer) toks = 1-cl->mbuffer; \
	cl->T = toks

	OTB_CHCL(cl);
	diff = PSCHED_TDIFF_SAFE(q->now, cl->t_c, (u32)cl->mbuffer, 0);
#ifdef OTB_DEBUG
	if (diff > cl->mbuffer || diff < 0 || PSCHED_TLESS(q->now, cl->t_c)) {
	    if (net_ratelimit())
		    printk(KERN_ERR "QOS: OTB - bad diff in charge, cl=%X diff=%lX now=%Lu then=%Lu j=%lu\n",
				   cl->classid, diff,
			   (unsigned long long) q->now,
				   (unsigned long long) cl->t_c,
				   jiffies);
		diff = 1000;
	}
#endif
	OTB_ACCNT (tokens,buffer,rate);
	OTB_ACCNT (ctokens,cbuffer,ceil);
	cl->t_c = q->now;
	OTB_DBG(5,2,"otb_chrg_clp cl=%X diff=%ld tok=%ld ctok=%ld\n",cl->classid,diff,cl->tokens,cl->ctokens);
	
	diff = 0;

	otb_change_class_mode(q,cl,&diff,inSend);

	if (was_in_wq) 
		otb_safe_rb_erase(&cl->pq_node,&q->wait_pq);

	if (OTB_IN_WQ(cl)) 
		otb_add_to_wait_tree (q,cl,diff);
      
#ifdef OTB_RATECM
	/* update rate counters */
	cl->sum_bytes += bytes; cl->sum_packets++;
#endif
}

/**
 * otb_do_events - make mode changes to classes
 *
 * Scans event queue for pending events and applies them.
 */
static void otb_do_events(struct otb_sched *q)
{
	int i, was_in_sq;
	int event_occured = 0;
	//	OTB_DBG(8,1,"otb_do_events l=%d root=%p rmask=%X\n",
	//	level,q->wait_pq.rb_node,q->row_mask[level]);
	for (i = 0; i < 500; i++) {
		struct otb_class *cl;
		long diff;
		rb_node_t *p = q->wait_pq.rb_node;
		if (!p) {
		    q->waits_for_events = 0;
			q->near_ev_cache = jiffies + HZ;
			goto do_events_fin;
		}
		while (p->rb_left) p = p->rb_left;

		cl = rb_entry(p, struct otb_class, pq_node);
		if (TS_GE(cl->pq_key,(jiffies+1))) {
			OTB_DBG(8,3,"otb_do_ev_ret delay=%ld\n",cl->pq_key - jiffies);
			q->near_ev_cache = cl->pq_key;
			goto do_events_fin;
		}
		otb_safe_rb_erase(p,&q->wait_pq);
		diff = PSCHED_TDIFF_SAFE(q->now, cl->t_c, (u32)cl->mbuffer, 0);
#ifdef OTB_DEBUG
		if (diff > cl->mbuffer || diff < 0 || PSCHED_TLESS(q->now, cl->t_c)) {
			if (net_ratelimit())
				printk(KERN_ERR "QOS: OTB - bad diff in events, cl=%X diff=%lX now=%Lu then=%Lu j=%lu\n",
				       cl->classid, diff,
				       (unsigned long long) q->now,
				       (unsigned long long) cl->t_c,
				       jiffies);
			diff = 1000;
		}
#endif
		was_in_sq = OTB_IN_SQ(cl);
		event_occured = 1;
		if((cl->ctype == OTB_INNER) && (INNER_Q(cl)->waits_for_events) && TS_GE(jiffies, INNER_Q(cl)->near_ev_cache)) {
			PSCHED_GET_TIME(INNER_Q(cl)->now);
			otb_do_events(INNER_Q(cl));
		}
		otb_change_class_mode(q,cl,&diff, was_in_sq);
	    if (OTB_IN_WQ(cl)) {
		    otb_add_to_wait_tree (q,cl,diff);
		}
	}
	if (net_ratelimit())
		printk(KERN_WARNING "QOS: OTB - too many events !\n");
	q->near_ev_cache = jiffies + HZ/10;
do_events_fin:
	if(event_occured)
		otb_update_send_info(q);
	return;
}

/* until must be grater than jiffies ! */
static void otb_delay_until(struct Qdisc *sch,unsigned long until)
{
	struct otb_sched *q = (struct otb_sched *)sch->data;
	if (netif_queue_stopped(sch->dev)) return;
	del_timer(&q->timer);
	q->timer.expires = until;
	add_timer(&q->timer);
	sch->flags |= TCQ_F_THROTTLED;
	sch->stats.overlimits++;
	OTB_DBG(3,1,"otb_deq until=%lu\n",until);
}

#define LINK_LAYER_LENGTH(skb) ((skb)->nh.raw - (skb)->data)

static __inline__ int shouldAggregate(struct otb_sched *q, struct otb_class *cl, struct sk_buff *start, int totalLen) 
{
  struct sk_buff *skb;
  return ( (totalLen < q->aggregation) &&  
		   (!(cl->un.leaf.q->q.qlen)) &&
		   ((skb = cl->un.leaf.q->q.next)->len - LINK_LAYER_LENGTH(skb) +  totalLen <= ((q->fragmentation == AOM_QOS_FRAG_DISABLE) ? 2*ETH_DATA_LEN : q->fragmentation)) && 
		   (!skb_is_nonlinear(skb)) && 
		   //((skb->priority & AOM_CLS_F_DONT_TUNNEL) == 0) && 
		   ((skb->expand_info==NULL) || ((SKB_GET_EXPAND_INFO_PARAM(skb, priority, EXPAND_TYPE_VAL) & AOM_CLS_F_DONT_TUNNEL) == 0)) && 
           //((SKB_OTB_SCH_CODE(skb) != OTB_MESSAGE_SHOULD_DROP_AT_INNER)) &&
           ((SKB_GET_EXPAND_INFO_PARAM(skb, skb_otb_sch_code, EXPAND_TYPE_VAL) != OTB_MESSAGE_SHOULD_DROP_AT_INNER)) &&
		   ((skb->expand_info==NULL) || (TS_GE(SKB_GET_EXPAND_INFO_PARAM(skb, skb_arrival_time, EXPAND_TYPE_VAL) + cl->obsolete, jiffies ))));
		   //(TS_GE(SKB_ARRIVAL_TIME(skb) + cl->obsolete, jiffies )));
}



static struct sk_buff *otb_dequeue(struct Qdisc *sch)
{
	struct otb_class *cl = NULL;
	struct sk_buff *skb = NULL;
	struct otb_sched *q = (struct otb_sched *)sch->data;
	int was_in_wq;
	struct stats_conntrack_aggregate* ct_stats = NULL;
	int dequeued = 0;

	DPRINTK("otb_dequeue was called\n");
	//OTB_DBG(3,1,"otb_deq dircnt=%d qlen=%d\n",skb_queue_len(&q->direct_queue),sch->q.qlen);

	if (!sch->q.qlen) return NULL;
	PSCHED_GET_TIME(q->now);

	/* do events */
	if (TS_GE(jiffies, q->near_ev_cache))
		otb_do_events(q);

	if ((q->root) && (q->root->cmode == OTB_RED)) {
		DPRINTK("otb_dequeue inner and red\n");
		goto no_dequeue;
	}

	/* try to dequeue direct packets as high prio (!) to minimize cpu work */
	if ((skb = __skb_dequeue(&q->direct_queue)) != NULL) {
		if (q->ctype == OTB_INNER) {
			sch->q.qlen--;
		} else if (q->ctype == OTB_LEAF) {
			sch->q.qlen --;
			struct Qdisc *tmp = ((struct Qdisc *)((char *)(q->parent_class->parent_qdisc) - 
											(unsigned long)(&((struct Qdisc *)0)->data)));
			tmp->q.qlen --;
		}

		if (atomic_read(&global_packet_number)>0)
			atomic_dec(&global_packet_number); 
		goto fin;
	}

	do {

		/* get skb */
		rb_node_t *p = q->send_pq.rb_node;
		if (!p) // no class ready to send
			goto no_dequeue;
		while (p->rb_left) 
			p = p->rb_left;	
		cl = rb_entry(p, struct otb_class, send_node);
		if((q->root) && (cl->ctype == OTB_INNER) && 
		   (INNER_Q(cl)->send_status == OTB_EXCEED) && (q->root->cmode != OTB_GREEN)) //Cannot send Exceed
			goto no_dequeue;
		was_in_wq = OTB_IN_WQ(cl);

		if(cl->ctype == OTB_LEAF) {
			struct sk_buff *start;
			skb = start = cl->un.leaf.q->dequeue(cl->un.leaf.q);
			if (unlikely(!skb)) {
				printk(KERN_ERR "(%s:%d) null skb\n", __func__, __LINE__);
				goto no_dequeue;
			}
			dequeued = 1;
			int totalLen = start->len;
			if ((cl->prio >= OTB_LOW) && (cl->prio <= OTB_HIGH)) {
				while ( skb && !skb_is_nonlinear(skb) && shouldAggregate(q, cl, skb, totalLen)) {
					cl->exstats.agg++;
					q->exstats.agg++;
					q->parent_class->parent_qdisc->exstats.agg++;
					skb->next = cl->un.leaf.q->dequeue(cl->un.leaf.q);
					if(atomic_read(&global_packet_number)>0)
						atomic_dec(&global_packet_number);
					skb = skb->next;  /* shouldAggregate check that the queue is not 
										 empty and therfore skb != NULL */         
					skb_pull(skb, LINK_LAYER_LENGTH(skb));
					totalLen += skb->len;
					dequeued++;
				}
			}

			/* Check if we did aggregate skbs */
			if (totalLen != start->len) {
				skb = aggregate(start, totalLen, GFP_ATOMIC);
				if (skb == NULL) {
					/* The only possibility to fail is due to memory shortage
					   In this case we need to requeue all skbs */
					printk(KERN_ERR "QOS: error in aggregation\n");
					skb = start;
					struct sk_buff *cur = skb->next;
					skb->next = NULL;
					while (cur) {
						skb_push(cur, LINK_LAYER_LENGTH(cur));
						struct sk_buff *tmp = cur->next;
						cur->next = NULL;
						__skb_queue_head(&cl->un.leaf.q->q, cur);
						dequeued--;
						cur = tmp;
					}
				}
			}
		} else 
			skb = cl->un.inner.q->dequeue(cl->un.inner.q);

		if (unlikely(!skb)) {
			DPRINTK(KERN_ERR "(%s:%d) null skb\n", __func__, __LINE__);
			return NULL;
		}
		if ( /* INNER case and the peer decided to drop it */
		   //( (q->ctype == OTB_INNER) && (SKB_OTB_SCH_CODE(skb) == OTB_MESSAGE_SHOULD_DROP_AT_INNER) ) || 
		   ( (q->ctype == OTB_INNER) && (SKB_GET_EXPAND_INFO_PARAM(skb, skb_otb_sch_code, EXPAND_TYPE_VAL) == OTB_MESSAGE_SHOULD_DROP_AT_INNER) ) || 
		     /* LEAF case and obselete time has passed */
		   //( (q->ctype == OTB_LEAF)  && (TS_GE(jiffies,( SKB_ARRIVAL_TIME(skb) + cl->obsolete ) )))) {
		   ( (q->ctype == OTB_LEAF)  && (TS_GE(jiffies,( SKB_GET_EXPAND_INFO_PARAM(skb, skb_arrival_time, EXPAND_TYPE_VAL) + cl->obsolete ) )))) {
#if 0
			DPRINTK("otb_dequeue drop obselete, arrival=%lu,jiffies=%lu\n",SKB_ARRIVAL_TIME(skb),jiffies); 
#endif
			DPRINTK("otb_dequeue drop obselete, arrival=%lu,jiffies=%lu\n",SKB_GET_EXPAND_INFO_PARAM(skb, skb_arrival_time, EXPAND_TYPE_VAL),jiffies); 
			sch->stats.drops++;
			cl->stats.drops++;
			cl->exstats.obsolete++;
			q->exstats.obsolete++;
			if (q->ctype == OTB_LEAF) {
				sch->q.qlen -= dequeued;
				struct Qdisc *tmp = ((struct Qdisc *)((char *)(q->parent_class->parent_qdisc) - 
													  (unsigned long)(&((struct Qdisc *)0)->data)));
				tmp->q.qlen -= dequeued;
			}
			if (!OTB_IN_SQ(cl)) {
				otb_safe_rb_erase(&cl->send_node,&q->send_pq);
				otb_update_send_info(q);
			}
			if(!cl->arrival_time)
			   cl->arrival_time = SKB_GET_EXPAND_INFO_PARAM(skb, skb_arrival_time, EXPAND_TYPE_VAL);
				//cl->arrival_time = SKB_ARRIVAL_TIME(skb);
			if( q->ctype == OTB_INNER ) {

				#if STATS_CONNTRACK_FLAG
				ct_stats = stats_conntrack_get(skb);
				if(ct_stats) {
					ct_stats->dropped.dir[q->direction].bytes += skb->len;
					ct_stats->dropped.dir[q->direction].packets ++; 
				}
				#endif
				if (atomic_read(&global_packet_number)>0)
					atomic_dec(&global_packet_number);
				kfree_skb(skb);
				skb = NULL;
			}/* leaf */
			else {
				/* mark upper layer drop code */
				//SKB_OTB_SCH_CODE(skb) = OTB_MESSAGE_SHOULD_DROP_AT_INNER;
				SKB_SET_EXPAND_INFO_PARAM_VAL(skb, skb_otb_sch_code, OTB_MESSAGE_SHOULD_DROP_AT_INNER);
				return skb; // shall be freed at root level
			}
		} else {
			cl->arrival_time = 0;
			if ((cl->direction == AOM_QOS_WAN_DIRECTION_IN) && (cl->ctype == OTB_INNER)) {
				int charge = (SKB_GET_EXPAND_INFO_PARAM(skb, comp_size, EXPAND_TYPE_VAL)>0) ? SKB_GET_EXPAND_INFO_PARAM(skb, comp_size, EXPAND_TYPE_VAL) : LENGTH_COMPENSATION(cl, skb);
				otb_charge_class (q,cl, charge , was_in_wq, 1);
			
			} else {
				otb_charge_class (q,cl,LENGTH_COMPENSATION(cl, skb), was_in_wq, 1);
			}
		}
	} while (skb == NULL);

fin:
	sch->flags &= ~TCQ_F_THROTTLED;
	if (q->ctype == OTB_LEAF) {
		sch->q.qlen -= dequeued;
		struct Qdisc *tmp = ((struct Qdisc *)((char *)(q->parent_class->parent_qdisc) - 
											  (unsigned long)(&((struct Qdisc *)0)->data)));
		tmp->q.qlen -= dequeued;
	}
	if(q->root) {
		if (q->direction == AOM_QOS_WAN_DIRECTION_IN) {
			int charge = (SKB_GET_EXPAND_INFO_PARAM(skb, comp_size, EXPAND_TYPE_VAL)>0) ? SKB_GET_EXPAND_INFO_PARAM(skb, comp_size, EXPAND_TYPE_VAL) : LENGTH_COMPENSATION(cl, skb);
			otb_charge_class (q,q->root, charge, (q->root->cmode != OTB_GREEN), 1);
		} else {
			otb_charge_class (q,q->root,LENGTH_COMPENSATION(cl, skb), (q->root->cmode != OTB_GREEN), 1);
		}
	} else
		otb_update_send_info(q);
  
	OTB_DBG(3,1,"otb_deq_end %s j=%lu skb=%p\n",sch->dev->name,jiffies,skb);
	if (!q->wait_pq.rb_node) 
		q->waits_for_events = 0;

	/* if dequeued from a valid class belonging to a rule */
	if ( (cl != NULL) && (q->ctype == OTB_LEAF) ) {
		/* packet tos marking */
		if ( cl->mark_tos ) 
			m_ip_mark_tos(skb,cl->tos_value,cl->tos_mask); 
	} /* originated from a valid class */

	//SKB_OTB_SCH_CODE(skb) = OTB_MESSAGE_OK;
	SKB_SET_EXPAND_INFO_PARAM_VAL(skb, skb_otb_sch_code, OTB_MESSAGE_OK);
	return skb;

no_dequeue:
	if( q->ctype == OTB_INNER )
		otb_delay_until (sch,q->near_ev_cache);
	return NULL;
}

/* try to drop from each class (by prio) until one succeed */
static unsigned int otb_drop(struct Qdisc* sch)
{
	struct otb_sched *q = (struct otb_sched *)sch->data;
	struct sk_buff *skb;
	int i;

	/* get skb */
	for (i = 0; i < OTB_HSIZE; i++) {
		struct list_head *l;
		list_for_each (l,q->hash+i) {
			struct otb_class *cl = list_entry(l,struct otb_class,hlist);
			if((cl->ctype == OTB_LEAF) && (cl->un.leaf.q->q.qlen)) {
			    skb = cl->un.leaf.q->dequeue(cl->un.leaf.q);
				if(!cl->arrival_time)
				    cl->arrival_time = SKB_GET_EXPAND_INFO_PARAM(skb, skb_arrival_time, EXPAND_TYPE_VAL);
				    //cl->arrival_time = SKB_ARRIVAL_TIME(skb);
				cl->stats.drops++;
				if (!cl->un.leaf.q->q.qlen)
				    otb_safe_rb_erase(&cl->send_node,&q->send_pq);
				goto drop_skb;
			} else if (cl->un.inner.q->ops->drop && 
					   cl->un.inner.q->ops->drop(cl->un.inner.q)) {
				cl->stats.drops++;
				if(INNER_Q(cl)->send_status == OTB_IDLE)
				    otb_safe_rb_erase(&cl->send_node,&q->send_pq);
				goto drop_end;
			}
		}
	}

	/* try to dequeue direct packets */
	if ((skb = __skb_dequeue(&q->direct_queue)) == NULL)
	    return 0;

drop_skb:
	kfree_skb(skb);
drop_end:
	otb_update_send_info(q);
	sch->stats.drops++;
	sch->q.qlen--;
	return 1;
}

/* reset all classes */
/* always caled under BH & queue lock */
static void otb_reset(struct Qdisc* sch)
{
  struct otb_sched *q = (struct otb_sched *)sch->data;
  int i;
  OTB_DBG(0,1,"otb_reset sch=%p, handle=%X\n",sch,sch->handle);
  DPRINTK("otb_reset was called\n");
  DPRINTK(KERN_INFO "Entered otb reset\n");
	/* reset classes */
	for (i = 0; i < OTB_HSIZE; i++) {
		struct list_head *p;
		list_for_each (p,q->hash+i) {
			struct otb_class *cl = list_entry(p,struct otb_class,hlist);
			if(cl->ctype == OTB_LEAF)
				qdisc_reset(cl->un.leaf.q);
			else
				qdisc_reset(cl->un.inner.q);
			cl->cmode = OTB_GREEN;
			cl->usage = 0;
			cl->power = 0;
			cl->arrival_time = 0;

			if (cl->pq_node.rb_color != -1) {
					otb_safe_rb_erase(&cl->pq_node, &q->wait_pq);
			}
			cl->pq_node.rb_color =- 1;

			if (cl->send_node.rb_color != -1) {
					otb_safe_rb_erase(&cl->send_node, &q->send_pq);
			}
			cl->send_node.rb_color =- 1;

#ifdef OTB_DEBUG		
			memset(&cl->send_node,255,sizeof(cl->send_node));
#endif
			}
	}
	if(q->root) {
	    struct otb_class *cl = q->root;
		qdisc_reset(cl->un.leaf.q); //is that needed here ? I do it just for safety.
		cl->cmode = OTB_GREEN;
		cl->usage = 0;
		cl->power = 0;
		cl->arrival_time = 0;

		if (cl->pq_node.rb_color != -1) {
				otb_safe_rb_erase(&cl->pq_node, &q->wait_pq);
		}
		cl->pq_node.rb_color =- 1;

#ifdef OTB_DEBUG
		memset(&cl->send_node,255,sizeof(cl->send_node));
#endif
	}
	/* reset queue */
	sch->flags &= ~TCQ_F_THROTTLED;
	del_timer(&q->timer);
	__skb_queue_purge(&q->direct_queue);
	sch->q.qlen = 0;
    q->waits_for_events = 0;
    q->send_status = OTB_IDLE;
	memset(&q->wait_pq,0,sizeof(q->wait_pq));
	memset(&q->send_pq,0,sizeof(q->send_pq));
#if 0
    q->power_cache = jiffies;
    q->near_ev_cache = jiffies;
#endif

}


static int otb_change(struct Qdisc *sch, struct rtattr *opt)
{
	struct otb_sched *q = (struct otb_sched*)sch->data;
	struct rtattr *tb[TCA_OTB_MAX];
	struct aom_otb_glob gopt;
	int i;
	unsigned char update_flag = 0;
	
	printk("otb_change was called sch 0x%x opt %p\n",sch->handle,opt);
	if (opt == NULL) {
		printk(KERN_ERR "QOS: got a null message buffer\n");
		return 0;
	}
	if( rtattr_parse(tb,TCA_OTB_MAX, RTA_DATA(opt), RTA_PAYLOAD(opt)) < 0) {
		printk(KERN_ERR "QOS: failed to parse message buffer\n");
		return -EINVAL;
	}
	if ( (tb[TCA_OTB_PARMS - 1] == NULL) || (RTA_PAYLOAD(tb[TCA_OTB_PARMS-1]) < sizeof(struct aom_otb_glob))) {
		// no data was configured for that entry 
		printk(KERN_ERR "QOS: no data was configured\n");
		return -EINVAL;
	} 

	sch_tree_lock(sch); 

	memcpy( &gopt , (struct aom_otb_glob *) RTA_DATA(tb[ TCA_OTB_PARMS-1]) , sizeof(struct aom_otb_glob) );
	printk(KERN_DEBUG "QOS: otb_change: mask is %x aggregation is %d fragmentation is %d\n", gopt.mask, gopt.aggregation, gopt.fragmentation);
  	if (q->ctype == OTB_LEAF) {
		if (gopt.mask & AGGREGATION_UPDATE) {
			
			if ( (gopt.aggregation != AOM_QOS_AGGREGATION_DISABLE) && 
				 (gopt.aggregation < AOM_QOS_AGGREGATION_MIN_SIZE)) {
				q->aggregation = AOM_QOS_AGGREGATION_MIN_SIZE;
			} else {
				q->aggregation = gopt.aggregation;
			}
		}
		if (gopt.mask & FRAGMENTATION_UPDATE) {
					
			if ( (gopt.fragmentation != AOM_QOS_FRAG_DISABLE) && 
				 (gopt.fragmentation < AOM_QOS_FRAGMENTATION )) {
				q->fragmentation = AOM_QOS_FRAGMENTATION;
			} else {
				q->fragmentation = gopt.fragmentation;
			}
		}
	} else if (q->ctype == OTB_INNER) {
		/* updating the strict priority option :  */
		if(gopt.mask & PRIORITY_STRICT_UPDATE) {
			if(!(q->flag & PRIORITY_STRICT_UPDATE)) {
				update_flag = 1;
				q->flag |= PRIORITY_STRICT_UPDATE;
			}
        } else {
			if(q->flag & PRIORITY_STRICT_UPDATE) {
				update_flag = 1;
				q->flag &=(~PRIORITY_STRICT_UPDATE);
			}
		}
      
		if(update_flag) {
			for (i = 0; i < OTB_HSIZE; i++) {
				/* scan classes in hash */
				struct list_head *p;
				list_for_each (p,q->hash+i) {
					struct otb_class *peer_cl = list_entry(p,struct otb_class,hlist);
					update_peer_priority_data(peer_cl,NULL,(q->flag & PRIORITY_STRICT_UPDATE));
					update_wan_priority_weights(peer_cl,q->root,(q->flag & PRIORITY_STRICT_UPDATE));
					update_peer_rules_priority_params(peer_cl, gopt.log_flag);
				}
			}
		}

    	DPRINTK(KERN_DEBUG "otb_change after update : q->flag  is %d\n", q->flag);
	} 
    sch_tree_unlock(sch);
	return 0;
}

static int otb_init(struct Qdisc *sch, struct rtattr *opt)
{
  struct otb_sched *q = (struct otb_sched*)sch->data;
  struct rtattr *tb[TCA_OTB_MAX];
  struct aom_otb_glob gopt;
  int i;
  DPRINTK("otb_init was called \n");

  if (opt == NULL) {
    printk(KERN_ERR "QOS: got a null message buffer\n");
    return 0;
  }
  if( rtattr_parse(tb,TCA_OTB_MAX, RTA_DATA(opt), RTA_PAYLOAD(opt)) < 0) {
    printk(KERN_ERR "QOS: failed to parse message buffer\n");
   return -EINVAL;
  }
  if ( (tb[TCA_OTB_PARMS - 1] == NULL) || (RTA_PAYLOAD(tb[TCA_OTB_PARMS-1]) < sizeof(struct aom_otb_glob))) {
    // no data was configured for that entry 
    printk(KERN_ERR "QOS: no data was configured\n");
    return -EINVAL;
  } 

  // sch_tree_lock(sch); 

  memcpy( &gopt , (struct aom_otb_glob *) RTA_DATA(tb[ TCA_OTB_PARMS-1]) , sizeof(struct aom_otb_glob) );
  printk(KERN_DEBUG "otb_init: type is %d link_layer_delta is %d fragmentation is %d aggregation is %d\n", gopt.ctype, gopt.link_layer_delta, gopt.fragmentation, gopt.aggregation);
  /* if acting as inner qdisc*/

  if ( (q->ctype = gopt.ctype) == OTB_INNER) {
	q->link_layer_delta = gopt.link_layer_delta;
        if(gopt.mask & PRIORITY_STRICT_UPDATE)
	  q->flag |= PRIORITY_STRICT_UPDATE;
          DPRINTK(KERN_DEBUG "QOS: otb_init : q->flag is %d\n",q->flag);
  
  }
  
  if ( (q->ctype = gopt.ctype) == OTB_LEAF) {
    /*******************************************/
    /* Sanity on the qos MTU for fragmentation */
    if ( (gopt.fragmentation != AOM_QOS_FRAG_DISABLE) && (gopt.fragmentation < AOM_QOS_FRAGMENTATION ) )
      q->fragmentation = AOM_QOS_FRAGMENTATION;
    else
      q->fragmentation = gopt.fragmentation;

    /*******************************************/
    /* Sanity on the aggregation size          */
    if ( (gopt.aggregation != AOM_QOS_AGGREGATION_DISABLE) && (gopt.aggregation < AOM_QOS_AGGREGATION_MIN_SIZE) )
      q->aggregation = AOM_QOS_AGGREGATION_MIN_SIZE;
    else
      q->aggregation = gopt.aggregation;

  }

  DPRINTK(KERN_DEBUG "QOS: otb_init - handle = %x , q->type = %d ,q->fragmentation = %d , q->aggregation = %d\n",sch->handle,q->ctype,q->fragmentation,q->aggregation); 
  
  q->parent_class = NULL;

  q->root = NULL;
  for (i = 0; i < OTB_HSIZE; i++)
    INIT_LIST_HEAD(q->hash+i);

  init_timer(&q->timer);
  /* init direct queue for passthrough */
  skb_queue_head_init(&q->direct_queue);

   q->max_qlen = sch->dev->tx_queue_len ;
   //q->max_qlen = dev_max_qlen;
  if (q->max_qlen < 2) /* some devices have zero tx_queue_len */
    q->max_qlen = 2;

  q->timer.function = otb_timer;
  q->timer.data = (unsigned long)sch;

#ifdef OTB_RATECM
  init_timer(&q->rttim);
  q->rttim.function = otb_rate_timer;
  q->rttim.data = (unsigned long)sch;
  q->rttim.expires = jiffies + HZ;
  add_timer(&q->rttim);
#endif
  q->send_status = OTB_IDLE;
  q->waits_for_events = 0;
#if 0
  q->power_cache = jiffies;
  q->near_ev_cache = jiffies;
#endif
  
  MOD_INC_USE_COUNT;
  // sch_tree_unlock(sch);
  return 0;
}

static int otb_dump(struct Qdisc *sch, struct sk_buff *skb)
{
  struct otb_sched *q = (struct otb_sched*)sch->data;
  unsigned char	 *b = skb->tail;
  struct rtattr *rta;
  struct aom_qos_xstats stats;

  OTB_QLOCK(sch);
  rta = (struct rtattr*)b;
  sch->stats.qlen = sch->q.qlen;
  RTA_PUT(skb, TCA_STATS, sizeof(sch->stats), &sch->stats);

  /* get common wan/peer extented statistics */
  memset(&stats,0,sizeof(struct aom_qos_xstats));
  stats.discarded = q->exstats.discarded;
  stats.obsolete = q->exstats.obsolete;
  stats.frag = q->exstats.frag;
  stats.agg = q->exstats.agg;
  stats.max_qlen = q->exstats.max_qlen;

  if (q->parent_class) {
     if ( q->parent_class->ceil->rate.rate )
        stats.bandwidth = q->parent_class->ceil->rate.rate / 125;
     else
        stats.bandwidth = 0;
     stats.bandwidth_inc = q->parent_class->exstats.bandwidth_inc;
     stats.bandwidth_dec = q->parent_class->exstats.bandwidth_dec;
  }
  else {
     stats.bandwidth = 0;
     stats.bandwidth_inc = 0;
     stats.bandwidth_dec = 0;
  }


  stats.mask |= AOM_QOS_STATS_DISCARDED;
  stats.mask |= AOM_QOS_STATS_OBSOLETE;
  stats.mask |= AOM_QOS_STATS_FRAGMENT;
  stats.mask |= AOM_QOS_STATS_AGGREGATE;
  stats.mask |= AOM_QOS_STATS_MAX_QLEN;
  stats.mask |= AOM_QOS_STATS_DYNAMIC_BANDWIDTH;
  RTA_PUT(skb, TCA_XSTATS, sizeof(struct aom_qos_xstats), &stats);     

  /* get wan specific stats */ 
  if (q->ctype == OTB_INNER) {
    /* Fill here wan's specific stats */
    ;
  } else {
    /* Fill here peer's specific stats */
    ;
  }

  OTB_QUNLOCK(sch);
  return skb->len;
rtattr_failure:
  OTB_QUNLOCK(sch);
  skb_trim(skb, skb->tail - skb->data);
  return -1;
}

static int otb_dump_class(struct Qdisc *sch, unsigned long arg,
	struct sk_buff *skb, struct tcmsg *tcm)
{
	struct otb_sched *q = (struct otb_sched*)sch->data;
	struct otb_class *cl = (struct otb_class*)arg;
	unsigned char	 *b = skb->tail;
	struct rtattr *rta;
	DPRINTK("otb_dump_class was called sch 0x%x cl 0x%x\n",sch->handle,cl->classid);

	OTB_QLOCK(sch);
	tcm->tcm_parent = TC_H_MAJ(cl->classid);//TC_H_ROOT;
	tcm->tcm_handle = cl->classid;
	tcm->tcm_info = 0;
	cl->stats.qlen = (cl->ctype == OTB_LEAF)?cl->un.leaf.q->q.qlen:cl->un.inner.q->q.qlen;
	rta = (struct rtattr*)b;

#ifdef OTB_RATECM
	cl->stats.bps = cl->rate_bytes/(OTB_EWMAC*OTB_HSIZE);
	cl->stats.pps = cl->rate_packets/(OTB_EWMAC*OTB_HSIZE);
#endif

	RTA_PUT(skb, TCA_STATS, sizeof(cl->stats), &cl->stats);
	if (q->ctype == OTB_INNER) {
		/* For now no stats are relevant for peer from a class */
		;
	} else {
		/* Fill in the stats relevant for the class of the rule */
		cl->exstats.mask |= AOM_QOS_STATS_DISCARDED;
		cl->exstats.mask |= AOM_QOS_STATS_OBSOLETE;
		cl->exstats.mask |= AOM_QOS_STATS_FRAGMENT;
		cl->exstats.mask |= AOM_QOS_STATS_AGGREGATE;
		cl->exstats.mask |= AOM_QOS_STATS_MAX_QLEN;
		cl->exstats.mask |= AOM_QOS_STATS_DYNAMIC_BANDWIDTH;
		cl->exstats.usage = cl->un.leaf.q->q.qlen;
		if (cl->un.leaf.q->ops->dump(cl->un.leaf.q, skb) < 0)
			printk(KERN_ERR "(%s:%d) ERROR dumping leaf stats\n", __func__, __LINE__);

		if (cl->direction == AOM_QOS_WAN_DIRECTION_OUT) {
			int size = sizeof(q->exstats.eprio_stats);
			struct aom_eprio_stats *pst = (void *)skb->tail-size;
			memcpy(&cl->exstats.eprio_stats,pst,size);
		}
		RTA_PUT(skb, TCA_XSTATS, sizeof(struct aom_qos_xstats), &(cl->exstats));       
	}
	OTB_QUNLOCK(sch);
	return skb->len;

rtattr_failure:
	OTB_QUNLOCK(sch);
	skb_trim(skb, b - skb->data);
	return -1;
}

static int otb_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
	struct Qdisc **old)
{
  struct otb_class *cl = (struct otb_class*)arg;
  struct otb_sched *q = (struct otb_sched *)new->data;
  DPRINTK("otb_graft was called sch 0x%x new 0x%x arg 0x%lx\n",sch->handle,new->handle,arg);
  if( !cl || (new == NULL)) { 
    printk(KERN_ERR "otb_graft ENOENT\n");
    return -ENOENT;
  }
  *old = NULL;
  sch_tree_lock(sch);
  sch->q.qlen -= cl->un.leaf.q->q.qlen;	
  qdisc_reset(cl->un.leaf.q);
  cl->un.inner.q = new;
  cl->un.inner.rules_must_use_peers_obsolete = 0;
  cl->un.inner.rules_must_use_peers_max_qlen = 0;
  cl->ctype = OTB_INNER;
  q->direction = cl->direction; 
  if(q->ctype == OTB_LEAF){
    q->parent_class = cl ;
    //q->max_qlen = set_max_qlen(cl->prio_data.obsolete[OTB_PASSTHROUGH],cl->ceil->rate.rate * AVERAGE_COMPRESSION_RATE);
    // if((dev_max_qlen)&&(q->max_qlen > dev_max_qlen))
    //		     q->max_qlen = dev_max_qlen; 
   
  } 
#if 0
  else
    /* max queue len for direct queue which is used for unclassified packets */
    q->max_qlen = 100 ;
#endif
  sch_tree_unlock(sch);
  return 0;
}

static struct Qdisc * otb_leaf(struct Qdisc *sch, unsigned long arg)
{
  struct otb_class *cl = (struct otb_class*)arg;
  DPRINTK("otb_qdisc_leaf\n");
  if (cl)
	  return (cl->ctype ? cl->un.inner.q : cl->un.leaf.q);

  return NULL;
}

static unsigned long otb_get(struct Qdisc *sch, u32 classid)
{
#ifdef OTB_DEBUG
  //struct otb_sched *q = (struct otb_sched *)sch->data;
#endif
  struct otb_class *cl = otb_find(classid,sch);
  DPRINTK("otb_get was called\n");
  if (cl) 
    cl->refcnt++;
  return (unsigned long)cl;
}

static void otb_destroy_filters(struct tcf_proto **fl)
{
  struct tcf_proto *tp;
  DPRINTK("otb_destroy_filters was called\n");
  while ((tp = *fl) != NULL) {
    *fl = tp->next;
    tp->ops->destroy(tp);
  }
}


static void otb_destroy_class(struct Qdisc* sch,struct otb_class *cl)
{
	struct otb_sched *q = (struct otb_sched *)sch->data;
	DPRINTK(KERN_ERR "otb_destroy_class sch 0x%x\n cl 0x%x\n",sch->handle,cl->classid);

	if(cl->ctype == OTB_LEAF) {
		// q->root->q.qlen equals zero
		if ((cl->send_node.rb_color != -1) && (cl != q->root))
			otb_safe_rb_erase(&cl->send_node,&q->send_pq);

		sch->q.qlen -= cl->un.leaf.q->q.qlen;
	   
		if (q->parent_class) {
				struct Qdisc *tmp = ((struct Qdisc *)((char *)(q->parent_class->parent_qdisc) - 
												(unsigned long)(&((struct Qdisc *)0)->data)));
				if (tmp) {
					tmp->q.qlen -= cl->un.leaf.q->q.qlen;
				}
		}
		
		   if(atomic_read(&global_packet_number)>0)
			   atomic_sub(cl->un.leaf.q->q.qlen, &global_packet_number); 
		qdisc_destroy(cl->un.leaf.q);
	} else {
		if (cl->send_node.rb_color != -1)
			otb_safe_rb_erase(&cl->send_node,&q->send_pq);

		sch->q.qlen -= cl->un.inner.q->q.qlen;
		qdisc_destroy(cl->un.inner.q);
	}

	qdisc_put_rtab(cl->rate);
	qdisc_put_rtab(cl->ceil);
	
#ifdef CONFIG_NET_ESTIMATOR
	qdisc_kill_estimator(&cl->stats);
#endif
	
	if(cl != q->root) {
	    /* note: this delete may happen twice (see otb_delete) */
	    list_del(&cl->hlist);
	} else
	    q->root = NULL;
		
	if (OTB_IN_WQ(cl)){
		otb_safe_rb_erase(&cl->pq_node,&q->wait_pq);
    }
	
	kfree(cl);
	otb_update_send_info(q);

}

/* always caled under BH & queue lock */
static void otb_destroy(struct Qdisc* sch)
{
	struct otb_sched *q = (struct otb_sched *)sch->data;
	int i;
DPRINTK("otb_destroy was called\n");
	del_timer_sync (&q->timer);
#ifdef OTB_RATECM
	del_timer_sync (&q->rttim);
#endif
        session_cache_clear(); 
	for (i = 0; i < OTB_HSIZE; i++) {
		struct list_head *p, *n;
		list_for_each_safe (p,n,q->hash+i) {
			struct otb_class *cl = list_entry(p,struct otb_class,hlist);
			otb_destroy_class (sch,cl);
		}
	}
	if(q->root) {
	    otb_destroy_class (sch,q->root);
	}

	otb_destroy_filters(&q->filter_list);
	__skb_queue_purge(&q->direct_queue);
	MOD_DEC_USE_COUNT;
}

static int otb_delete(struct Qdisc *sch, unsigned long arg)
{
	struct otb_sched *q = (struct otb_sched *)sch->data;
	struct otb_class *cl = (struct otb_class*)arg;
	DPRINTK("otb_delete was called sch 0x%x\n",sch->handle);
	if (cl->filter_cnt)
		return -EBUSY;
	sch_tree_lock(sch);
        session_cache_clear(); 
	/* delete from hash and active; remainder in destroy_class */
	list_del_init(&cl->hlist);
	// q->root->q.qlen equals zero
	if(cl->ctype == OTB_LEAF) {
		if(cl->un.leaf.q->q.qlen && (cl->cmode != OTB_RED)) {
			otb_safe_rb_erase(&cl->send_node,&q->send_pq);
			qdisc_destroy(cl->un.leaf.q);
		}
	} else {
		if((INNER_Q(cl)->send_status != OTB_IDLE) && (cl->cmode != OTB_RED))
			otb_safe_rb_erase(&cl->send_node,&q->send_pq);
	}
	
	if (OTB_IN_WQ(cl)){
	  otb_safe_rb_erase(&cl->pq_node,&q->wait_pq);
      cl->cmode = OTB_GREEN ;
    }

	if(cl == q->root)
	    q->root = NULL;

	if (--cl->refcnt == 0)
		otb_destroy_class(sch,cl);

	otb_update_send_info(q);
	if ((q->send_status == OTB_IDLE) && (q->ctype == OTB_LEAF) && 
	  (q->parent_class->send_node.rb_color != -1)) {
		  otb_safe_rb_erase(&q->parent_class->send_node, &q->parent_class->parent_qdisc->send_pq);
	}
	sch_tree_unlock(sch);
	return 0;
}

static void otb_put(struct Qdisc *sch, unsigned long arg)
{
#ifdef OTB_DEBUG
  //struct otb_sched *q = (struct otb_sched *)sch->data;
#endif
 struct otb_class *cl = (struct otb_class*)arg;
 DPRINTK("otb_put was called\n");
 if (--cl->refcnt == 0)
   otb_destroy_class(sch,cl);
}


static void update_wan_priority_weights (struct otb_class * peer_cl, struct otb_class * wan_cl,unsigned int flag)
{
	int i;
	struct prio_params* calculated_prio_data = get_qos_prio_params(wan_cl->rate->rate.rate, flag);
    memcpy (peer_cl->wan_prio_bonus, calculated_prio_data->bonus, sizeof(u32)*OTB_MAX_PRIO);

	printk(KERN_DEBUG "QOS: WAN PRIORITY BONUS :\n"); 
	for (i= 0;i<OTB_MAX_PRIO;i++)
		printk(KERN_DEBUG "QOS: prio %d = %d\n",i,peer_cl->wan_prio_bonus[i]); 

	return;
}



static void update_peer_priority_data(struct otb_class * cl,struct aom_otb_glob *hopt,unsigned int flag)
{
	if(hopt) {
		// user space has configured prio params. copy to the peers class
		if (hopt->rate.flags & AOM_QOS_PRIO_WEIGHTS) {
			DPRINTK(KERN_DEBUG "update PRIO WEIGHTS\n"); 
			memcpy(cl->prio_data.bonus ,hopt->rate.prio_weights,sizeof(u32)*OTB_MAX_PRIO);
		}
		if (hopt->rate.flags & AOM_QOS_PRIO_OBSOLETE) {
			DPRINTK(KERN_DEBUG "update PRIO OBSOLETE\n"); 
			memcpy(cl->prio_data.obsolete ,hopt->rate.prio_obsolete,sizeof(u32)*OTB_MAX_PRIO);
			cl->un.inner.rules_must_use_peers_obsolete = 
				(hopt->rate.flags & AOM_QOS_PRIO_OBSOLETE_ARE_DEFAULTS) ? 0 : 1;
		} 
		if (hopt->rate.flags & AOM_QOS_PRIO_MAX_QLEN) {
			DPRINTK(KERN_DEBUG "update PRIO MAX_QLEN\n"); 
			memcpy(cl->prio_data.max_qlen ,hopt->rate.prio_max_qlen,sizeof(u32)*OTB_MAX_PRIO);
			cl->un.inner.rules_must_use_peers_max_qlen = 
				(hopt->rate.flags & AOM_QOS_PRIO_MAX_QLEN_ARE_DEFAULTS) ? 0 : 1;
		} 
	} else {
		// if the user space does not configure the peer we must try to configure it ourselves
		// this means that if tcp acceleration is enabled we give incorrect numbers.
		printk(KERN_ERR "QOS: user space has not supplied prio params!!!\n"); 
		u32 rate = cl->ceil->rate.rate ;
		u32 wans_rate = rate;
		if (cl->parent_qdisc->root && cl->parent_qdisc->root->ceil) {
			wans_rate = cl->parent_qdisc->root->ceil->rate.rate;
		}
		unsigned long peer_id;
		AOM_QOS_RES_PEER_ID(cl->classid, peer_id);
		calculate_qos_prio_params(rate, wans_rate, peer_id, flag, &cl->prio_data);
	}

	int i;
	char buf[100];

	sprintf (buf, KERN_DEBUG "QOS: CLASS PRIORITY WEIGHTS: ");
	for (i=0;i<OTB_MAX_PRIO;i++)
		sprintf(buf + strlen(buf), " %d,",cl->prio_data.bonus[i]);
	sprintf(buf + strlen(buf), "\n"); 
	printk(buf);
	
	sprintf (buf, KERN_DEBUG "QOS: CLASS PRIORITY OBSOLETE:");
	for (i=0;i<OTB_MAX_PRIO;i++)
		sprintf(buf + strlen(buf), " %d,",cl->prio_data.obsolete[i]);
	sprintf(buf + strlen(buf), "\n");    
	printk(buf);

	sprintf (buf, KERN_DEBUG "QOS: CLASS PRIORITY MAX QLEN:");  
	for (i=0;i<OTB_MAX_PRIO;i++)
		sprintf(buf + strlen(buf), " %d,",cl->prio_data.max_qlen[i]);
	sprintf(buf + strlen(buf), "\n"); 
	printk(buf);

	return;
}



void update_rule_priority_params(struct otb_class *rule_cl, struct otb_class * peer_cl, int log_flag)
{        
	unsigned int max_qlen_rate = 0;
	struct prio_params* calculated_prio_data;

	if (!peer_cl->un.inner.rules_must_use_peers_obsolete &&
		rule_cl->ceil->rate.rate < (peer_cl->ceil->rate.rate * AVERAGE_COMPRESSION_RATE)) {
		/* if a limit has been configured for the rule we must adjust its data according to
		 * the limit and not the peers rate (if the limit is much lower than the peer rate we'll
		 * get a too small obsolete and bonus. */
        calculated_prio_data = get_qos_prio_params(rule_cl->ceil->rate.rate, 0);
        rule_cl->obsolete = calculated_prio_data->obsolete[rule_cl->prio];

		max_qlen_rate = rule_cl->ceil->rate.rate;
		printk(KERN_DEBUG "QOS: update_rule_priority_params takes info from the rule.\n");
	} else {
        rule_cl->obsolete = peer_cl->prio_data.obsolete[rule_cl->prio];
		max_qlen_rate = peer_cl->ceil->rate.rate;
		printk(KERN_DEBUG "QOS: update_rule_priority_params takes info from the peer. rules_must_use_peers_obsolete = %d\n", 
			   peer_cl->un.inner.rules_must_use_peers_obsolete);
	}
	/* prio_bonus should come from the link (so that it wont ruin the priority calculations for
	 * the link just because one of the rules has a low limit) */
	rule_cl->prio_bonus = peer_cl->prio_data.bonus[rule_cl->prio];
	rule_cl->max_qlen   = peer_cl->prio_data.max_qlen[rule_cl->prio];

	if (!peer_cl->un.inner.rules_must_use_peers_max_qlen && 
		rule_cl->max_qlen == 0) {
		/* No max_qlen has been configured or dtermined */
	    if(rule_cl->ceil->rate.rate == AOM_QOS_NO_BANDWIDTH_LIMIT) {
			DPRINTK("rule limit is AOM_QOS_NO_BANDWIDTH_LIMIT\n");
		}
        DPRINTK(KERN_DEBUG "QOS: max_qlen_rate = %d\n", max_qlen_rate); 
		rule_cl->max_qlen = calculate_max_qlen(rule_cl->obsolete,max_qlen_rate);
		if (rule_cl->max_qlen > DEV_MAX_QLEN)
			rule_cl->max_qlen = DEV_MAX_QLEN; 
	}
	if (rule_cl->max_qlen < 4)
		rule_cl->max_qlen = 4 ;

	if(log_flag == 1) {
	printk(KERN_DEBUG "QOS: update/create rule class id = 0x%x ,  prio=%d,bonus=%d,obsolete=%d,max_qlen=%d\n",
		 rule_cl->classid,rule_cl->prio,rule_cl->prio_bonus,rule_cl->obsolete,rule_cl->max_qlen);          
}
}


static void update_peer_rules_priority_params(struct otb_class *  peer_cl, int log_flag)
{
	int i;
   
	struct list_head * p ; 
    for (i=0;i<OTB_HSIZE;i++) {
		list_for_each(p,INNER_Q(peer_cl)->hash+i) {
			struct otb_class * rule_cl = list_entry(p,struct otb_class,hlist);
			update_rule_priority_params(rule_cl, peer_cl, log_flag);
		}  
	}        
}   

static int otb_change_class(struct Qdisc  *sch, 
							u32           classid, 
							u32           parentid, 
							struct rtattr **tca, 
							unsigned long *arg)
{
	int err = -EINVAL;
	struct otb_sched *q = (struct otb_sched *)sch->data;
	struct otb_class *cl = (struct otb_class*)*arg;
	struct rtattr *opt = tca[TCA_OPTIONS-1];
	struct qdisc_rate_table *rtab = NULL, *ctab = NULL;
	struct rtattr *tb[TCA_OTB_MAX];
	struct aom_otb_glob *hopt;
	unsigned char  update_flag = 0;
	int i ;
	DPRINTK("otb_change_class was called \n");
	/* extract all subattrs from opt attr */
	if (!opt || rtattr_parse(tb, TCA_OTB_MAX, RTA_DATA(opt), RTA_PAYLOAD(opt)) ||
		tb[TCA_OTB_PARMS-1] == NULL ||
		RTA_PAYLOAD(tb[TCA_OTB_PARMS-1]) < sizeof(*hopt) ) {
		
		printk(KERN_ERR "QOS: otb_change_class non valid message was sent\n");
		goto failure;
	}
	
	hopt = RTA_DATA(tb[TCA_OTB_PARMS-1]);
	
	rtab = qdisc_get_rtab(&hopt->rate.rate, tb[TCA_OTB_RTAB-1]);
	ctab = qdisc_get_rtab(&hopt->rate.ceil, tb[TCA_OTB_CTAB-1]);
  
	if (!rtab || !ctab) {
		printk(KERN_ERR "QOS: otb_change_class NULL rtab or ctab\n");
		goto failure;
	}

	if (!cl) { /* new class */
		struct Qdisc *new_q;
		/* check for valid classid */
		if (!classid || TC_H_MAJ(classid^sch->handle) || otb_find(classid,sch)) {
			printk(KERN_ERR "QOS: otb_change_class bad classid %d\n",classid);
			goto failure;
		}
		err = -ENOBUFS;
		if ((cl = kmalloc(sizeof(*cl), GFP_KERNEL)) == NULL)
			goto failure;
		memset(cl, 0, sizeof(*cl));
		cl->parent_qdisc = q;
		cl->refcnt = 1;
		cl->direction = q->direction;
		/* define class always as LEAF due to internal queue - will be changed with graft */
		cl->ctype = OTB_LEAF; //hopt->ctype;
		INIT_LIST_HEAD(&cl->hlist);
#		ifdef OTB_DEBUG
			cl->magic = OTB_CMAGIC;
#		endif

		new_q = qdisc_create_dflt(sch->dev, (cl->direction ?
					     &eprio_qdisc_ops: &pfifo_qdisc_ops));
		if (!new_q)
			printk(KERN_ERR "(%s:%d) err: failed init leaf\n",__func__, __LINE__);
		sch_tree_lock(sch);
		session_cache_clear();
		/* leaf (we) needs elementary qdisc */
		cl->un.leaf.q = new_q ? new_q : &noop_qdisc;
		cl->classid = classid;
		/* set class to be in OTB_GREEN state */
		cl->tokens = hopt->rate.buffer;
		cl->ctokens = hopt->rate.cbuffer;
		cl->mbuffer = 60000000; /* 1min */
		PSCHED_GET_TIME(cl->t_c);
		cl->cmode = OTB_GREEN;
		/* check if we dealing with a class which should manage all peers */
		if ((q->ctype == OTB_INNER) && (TC_H_MIN(classid) == AOM_QOS_WAN_PEERS_ID) ) {
			DPRINTK(KERN_DEBUG "otb_change_class : Adding root Class! ");
			/* attach to the root class */
			if(q->root)
				otb_destroy_class(sch,q->root);
			q->root = cl;
		} else {
			DPRINTK(KERN_DEBUG "otb_change_class : Adding a normal Class! ");
			/* attach to the hash list and parent's family */
			list_add_tail(&cl->hlist, q->hash+otb_hash(classid));
		}
//#ifdef OTB_DEBUG
		cl->send_node.rb_color = -1;
		cl->pq_node.rb_color = -1;
//#endif
	} else {

		/******** UPDATE CLASS : Only for peer and wan(root class) *******************/

		sch_tree_lock(sch);
		session_cache_clear(); 
		if (hopt->ctype == OTB_INNER) {
			if (hopt->mask & BANDWIDTH_UPDATE) {
				cl->usage = 0;

                                if (ctab->rate.rate > cl->ceil->rate.rate) {
                                   cl->exstats.bandwidth_inc++;
                                }
                                else if (ctab->rate.rate < cl->ceil->rate.rate) {
                                   cl->exstats.bandwidth_dec++;
                                }

				if (cl->ceil) {
					qdisc_put_rtab(cl->ceil);
				}

				cl->ceil = ctab;
				cl->cbuffer = cl->ctokens = hopt->rate.cbuffer;

				if((q->ctype == OTB_INNER) && (TC_H_MIN(classid)== AOM_QOS_WAN_PEERS_ID)) {
					/* Update bandwidth of wan : update all peers wan priority wights*/
					if(!(q->flag & PRIORITY_STRICT_UPDATE)) {
						for (i = 0; i < OTB_HSIZE; i++) {
							struct list_head *p;
							/* scan classes in hash */
							list_for_each (p,q->hash+i) {
								unsigned long peer_id;
								struct otb_class *peer_cl = list_entry(p,struct otb_class,hlist);
								update_wan_priority_weights(peer_cl,cl,0);
								
								// if the new wan rate is lower than the non link bandwidth we must update the non links params
								AOM_QOS_RES_PEER_ID(peer_cl->classid, peer_id);
                                if (peer_id == AOM_QOS_NON_PEERED_ID) {
									update_peer_priority_data(peer_cl,NULL,0);
								}
							}
						}
					}

				} else {
					/* Update bandwidth of peer : update peer priority data and the priority data 
					   of all peer's rules */
					if(!(q->flag & PRIORITY_STRICT_UPDATE)) {
						update_peer_priority_data(cl,hopt,0);
						update_flag = 1;
					}
				}                     
				DPRINTK(KERN_DEBUG "QOS: BANDWIDTH_UPDATE- rate %d ceil %d classid %d\n",
                                 cl->rate->rate.rate,cl->ceil->rate.rate,classid);
			}
			if ((hopt->mask & EXCEED_UPDATE) && (q->ctype == OTB_INNER) && 
				( TC_H_MIN(classid) == AOM_QOS_WAN_PEERS_ID )) {
				cl->usage = 0;
				if (cl->rate) {
					qdisc_put_rtab(cl->rate); 
				}
				cl->rate = rtab;	
				cl->buffer = cl->tokens = hopt->rate.buffer;
						  
				DPRINTK(KERN_DEBUG "QOS: EXCEED_UPDATE- rate %d ceil %d calssid %d\n",cl->rate->rate.rate,cl->ceil->rate.rate,classid);
			}
			char buf[100];
			if (hopt->mask & PRIORITY_WEIGHTS_UPDATE) {  
				memcpy(cl->prio_data.bonus ,hopt->rate.prio_weights,sizeof(u32)*OTB_MAX_PRIO);
				update_flag = 1;
				
                sprintf (buf, KERN_DEBUG "QOS: update PRIO WEIGHTS:");
				for (i=0;i<OTB_MAX_PRIO;i++)
					sprintf(buf + strlen(buf), " %d,",cl->prio_data.bonus[i]);
				sprintf(buf + strlen(buf), "\n"); 
				DPRINTK(buf);
			}
			if (hopt->mask & PRIORITY_OBSOLETE_UPDATE) {
				memcpy(cl->prio_data.obsolete ,hopt->rate.prio_obsolete,sizeof(u32)*OTB_MAX_PRIO);
				update_flag =1;
				
				// the following flag is set when updating the obsolete. this is temporary 
				// because its ugly. eventually we'll make this a prorperty of a peer.
				cl->un.inner.rules_must_use_peers_obsolete = 
					(hopt->rate.flags & AOM_QOS_PRIO_OBSOLETE_ARE_DEFAULTS) ? 0 : 1;
				
				DPRINTK("at %s. line %d. cl->un.inner.rules_must_use_peers_obsolete: %d. flags: %d\n",__FUNCTION__,__LINE__,
					   cl->un.inner.rules_must_use_peers_obsolete, hopt->rate.flags);

                sprintf (buf, KERN_DEBUG "QOS: update PRIO OBSOLETE:");
				for (i=0;i<OTB_MAX_PRIO;i++)
					sprintf(buf + strlen(buf), " %d,",cl->prio_data.obsolete[i]);
				sprintf(buf + strlen(buf), "\n"); 
				DPRINTK(buf);
			} 
			if (hopt->mask & PRIORITY_MAX_QLEN_UPDATE) {
				update_flag = 1;
				memcpy(cl->prio_data.max_qlen ,hopt->rate.prio_max_qlen,sizeof(u32)*OTB_MAX_PRIO);
				
				cl->un.inner.rules_must_use_peers_max_qlen = 
					(hopt->rate.flags & AOM_QOS_PRIO_MAX_QLEN_ARE_DEFAULTS) ? 0 : 1;
            
                sprintf (buf, KERN_DEBUG "QOS: update PRIO_MAX_QLEN:");
				for (i=0;i<OTB_MAX_PRIO;i++)
					sprintf(buf + strlen(buf), " %d,",cl->prio_data.max_qlen[i]);
				sprintf(buf + strlen(buf), "\n"); 
				DPRINTK(buf);
			} 
		}

		if(update_flag == 1)
			update_peer_rules_priority_params(cl, hopt->log_flag);
		    
		sch_tree_unlock(sch);
		*arg = (unsigned long)cl;
		return 0;
	
	}  /****************** END of Update operation **************************/
  
	/* priority is relevant only for leafs = rules 
	   for now support also peers, configuration should take care of it */
	if ((cl->prio = hopt->rate.prio) >= OTB_MAX_PRIO) {
		/* set to default prio */
		cl->prio = OTB_DEFAULT_PRIO;
	}
  
	cl->buffer = hopt->rate.buffer;
	cl->cbuffer = hopt->rate.cbuffer;
	cl->usage = 0;
	cl->arrival_time = 0;
	/* rate is exceed for peer and desired for rule */
	if (cl->rate) 
		qdisc_put_rtab(cl->rate); 
	cl->rate = rtab;
	/* ceil is limit for both peer and rule */
	if (cl->ceil) 
		qdisc_put_rtab(cl->ceil);
	cl->ceil = ctab;
  
	/* parameters pending on type of class */
	if (q->ctype == OTB_LEAF) { 
		/* TOS value */
		if (hopt->rate.flags & AOM_OTB_OPT_TOS_MARK) {
			cl->tos_value = hopt->rate.tos_field;
			cl->tos_mask = hopt->rate.tos_mask;
			cl->mark_tos = 1;
		}
		else
			cl->mark_tos = 0;
		
		cl->exceed = (hopt->rate.flags & AOM_OTB_OPT_EXCEED);
		cl->link_layer_delta = q->parent_class->link_layer_delta;
		update_rule_priority_params(cl, q->parent_class, hopt->log_flag);   
	} 
	else if (hopt->ctype == OTB_INNER) { 
		/* is exceed allowed */
		update_peer_priority_data(cl,hopt,(q->flag & PRIORITY_STRICT_UPDATE));
		update_wan_priority_weights(cl,q->root,(q->flag & PRIORITY_STRICT_UPDATE));
		cl->link_layer_delta = q->link_layer_delta;
	}
  
	sch_tree_unlock(sch);

	printk(KERN_DEBUG "QOS: New Class- classid %x prio %d, rate %d ceil %d\n",classid,cl->prio, cl->rate->rate.rate,cl->ceil->rate.rate);
	*arg = (unsigned long)cl;
	return 0;

failure:
	if (rtab) qdisc_put_rtab(rtab);
	if (ctab) qdisc_put_rtab(ctab);

	return err;
}

static struct tcf_proto **otb_find_tcf(struct Qdisc *sch, unsigned long arg)
{
  struct otb_sched *q = (struct otb_sched *)sch->data;
  struct tcf_proto **fl = &q->filter_list;
  DPRINTK("otb_find_tcf was called\n");
  if (q->ctype == OTB_INNER)
    return NULL;
  return fl;
}

static unsigned long otb_bind_filter(struct Qdisc *sch, unsigned long parent,
	u32 classid)
{
  struct otb_sched *q = (struct otb_sched *)sch->data;
  struct otb_class *cl = otb_find (classid,sch);
  DPRINTK("otb_bind_filter was called\n");
  if (q->ctype == OTB_INNER)
    return 0; /* inner doesn't supprt filters */
  if (cl)
    (q->filter_cnt)++;
  return (unsigned long)cl;
}

static void otb_unbind_filter(struct Qdisc *sch, unsigned long arg)
{
  struct otb_sched *q = (struct otb_sched *)sch->data;
  //struct otb_class *cl = (struct otb_class *)arg;
  //OTB_DBG(0,2,"otb_unbind q=%p cl=%p fref=%d\n",q,cl,cl?cl->filter_cnt:q->filter_cnt);
  if (q->ctype == OTB_INNER)
    return;
  q->filter_cnt--;
}

static void otb_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
  struct otb_sched *q = (struct otb_sched *)sch->data;
  struct list_head *p;
  int i;
  DPRINTK("otb_walk was called\n");
  if (arg->stop)
    return;

  /* get the root class if exists */
  if (q->root){
    struct otb_class *cl = q->root;
    if (arg->count < arg->skip) {
      arg->count++;
    } else if (arg->fn(sch, (unsigned long)cl, arg) < 0) {
      arg->stop = 1;
      return;
    }
    else
      arg->count++;
  }

  /* scan all classes */
  for (i = 0; i < OTB_HSIZE; i++) {
    /* scan classes in hash */
    list_for_each (p,q->hash+i) {
      struct otb_class *cl = list_entry(p,struct otb_class,hlist);
      if (arg->count < arg->skip) {
	arg->count++;
	continue;

      }
      if (arg->fn(sch, (unsigned long)cl, arg) < 0) {
	arg->stop = 1;
	return;
      }
      arg->count++;
    }
  } /* end scanning classes */
}





static struct Qdisc_class_ops otb_sch_class_ops =
{
    otb_graft,
    otb_leaf,
    otb_get,
    otb_put,
    otb_change_class,
    otb_delete,
    otb_walk,

    otb_find_tcf,
    otb_bind_filter,
    otb_unbind_filter,

    otb_dump_class,
};

struct Qdisc_ops otb_sch_qdisc_ops =
{
    NULL,
    &otb_sch_class_ops,
    AOM_QOS_OTB_SCH_QDISC_NAME,
    sizeof(struct otb_sched),

    otb_enqueue,
    otb_dequeue,
    otb_requeue,
    otb_drop,

    otb_init,
    otb_reset,
    otb_destroy,
    otb_change,

    otb_dump,
};


void otb_update_delta(struct Qdisc *wan, u32 realm, int delta, u8 is_part_of_aggregate)
{
  struct otb_sched *sch = (struct otb_sched *)wan->data;
  unsigned long old_ts = sch->near_ev_cache;
  
	/* for packets that are part of a post-acc aggregate we deduct the ethernet header from the
	 * delta to make sure we charge the header onlt once for each aggregate. */
	int adjusted_delta;
    
  if (sch->root) {
		adjusted_delta = is_part_of_aggregate ? delta - sch->root->link_layer_delta : delta;
		otb_charge_class(sch, sch->root, adjusted_delta, (sch->root->cmode != OTB_GREEN), OTB_IN_SQ(sch->root));
  }
  
  u32 classid;
  AOM_QOS_RES_PEER_CLASS_ID(realm, classid);
  struct otb_class *peer_cl = otb_find(classid, wan);

  if (peer_cl != NULL) {
		adjusted_delta = is_part_of_aggregate ? delta - peer_cl->link_layer_delta : delta;
		otb_charge_class(sch, peer_cl, adjusted_delta, OTB_IN_WQ(peer_cl), OTB_IN_SQ(peer_cl));
  }

  if (old_ts != sch->near_ev_cache) {
		  otb_delay_until (wan ,sch->near_ev_cache);
  }
}


extern struct Qdisc *find_wan_qdisc(u32 classid);

static int recursive_stats_reset(struct otb_class *cl)
{
		if (!cl) {
				return 0;
		}
		
		/* reseting class stats */
		memset(&cl->stats, 0, sizeof(struct tc_stats)); 
		memset(&cl->xstats, 0, sizeof(struct tc_htb_xstats));
		memset(&cl->exstats, 0, sizeof(struct aom_qos_xstats)); 
		
		if (cl->ctype == OTB_LEAF) {
				return 0;
		}

		/* resseting qdisc */
		struct Qdisc *q = cl->un.inner.q;
		struct otb_sched *sch = (struct otb_sched *)q->data;
		if (!sch) {
				return 0;
		}
		q->stats.bytes = q->stats.packets = q->stats.drops = 0;
		memset(&sch->exstats, 0, sizeof(struct aom_qos_xstats));

		int i;
		for (i = 0; i < OTB_HSIZE; i++) {
				struct list_head *p;
				list_for_each (p,sch->hash+i) {
						struct otb_class *cl = list_entry(p,struct otb_class,hlist);				
						recursive_stats_reset(cl);
				}
		}
		return 0;
}


static struct otb_class *find_link_class(u32 classid)
{
		struct Qdisc *wanq;
		struct otb_sched *sch; 
		
		wanq = find_wan_qdisc(classid);
		if (!wanq || !(sch = (struct otb_sched *)wanq->data)) {
				PERROR("could not find classid %x wan is %p\n",classid, wanq);
				return NULL;
		}
		
		u32 peerid;
		AOM_QOS_RES_PEER_CLASS_ID(classid, peerid);
		struct otb_class *peer_cl = otb_find(peerid, wanq);
		return peer_cl;  
}


static int wan_reset(u32 classid)
{
		struct Qdisc *wanq;
		struct otb_sched *sch; 
		
		wanq = find_wan_qdisc(classid);
		if (!wanq || !(sch = (struct otb_sched *)wanq->data)) {
				PERROR("could not find classid %x\n",classid);
				return -EINVAL;
		}
		
		/* resetting wan qdisc stats */
		wanq->stats.bytes = wanq->stats.packets = wanq->stats.drops = 0;
		memset(&sch->exstats, 0, sizeof(struct aom_qos_xstats));

		/* resetting root class stats */
		if (sch->root) {
				memset(&sch->root->stats, 0, sizeof(struct tc_stats)); 
				memset(&sch->root->xstats, 0, sizeof(struct tc_htb_xstats));
				memset(&sch->root->exstats, 0, sizeof(struct aom_qos_xstats)); 
		}

		int i;
		for (i = 0; i < OTB_HSIZE; i++) {
				struct list_head *p;
				list_for_each (p,sch->hash+i) {
						struct otb_class *cl = list_entry(p,struct otb_class,hlist);				
						recursive_stats_reset(cl);
				}
		}
		return 0;
}


static int link_reset(u32 classid)
{
		struct otb_class *cl = find_link_class(classid);
		return recursive_stats_reset(cl);
}

extern int checkvalidity(struct nlmsghdr *n, int expcmd, struct rtattr **xsla, int attid);

int xsl_reset_qos_counters(struct sk_buff *skb, struct nlmsghdr *n, void *arg)
{
        struct rtattr **xsla = arg;
		struct rtattr *rta;
		int type;
		int classid;
		int rc;
		int index = XSL_CTRL_ATT_RESET_TYPE - 1;
		rc = checkvalidity(n, XSL_CTRL_CMD_RESET_COUNTERS, xsla, index);

		if (rc) {
				PERROR("Validity check failed\n");
				return rc;
		}

		if ( xsla[index]->rta_type != XSL_CTRL_ATT_RESET_TYPE) {
				PERROR("Invalid type %u\n", xsla[index]->rta_type);
				return -EINVAL;
		}
		type = *((int *)(RTA_DATA(xsla[index])));
		
		rta = xsla[XSL_CTRL_ATT_CLASSID - 1];
		if (rta->rta_type != XSL_CTRL_ATT_CLASSID) {
				PERROR("Invalid type %u\n", rta->rta_type);
				return -EINVAL;
		}

		classid = *((int *)(RTA_DATA(xsla[XSL_CTRL_ATT_CLASSID - 1])));
		PDEBUG("type is %d classid is %x\n",type, classid);

		local_bh_disable();
		switch (type )
		{
		case WAN_RESET:
				rc = wan_reset(classid);
				break;
		case LINK_RESET:
				rc = link_reset(classid);
				break;
        case GLOBAL_RESET_STAT:
                global_reset_stat();
                rc = 0;
				break;
		default:
				PERROR("invalid reset type %u\n", type);
				rc = -EINVAL;
				break;
		}
		local_bh_enable();
		return rc;
}

int xsl_set_hysteresis(struct sk_buff *skb, struct nlmsghdr *n, void *arg)
{
	struct rtattr **xsla = arg;
	int val;
	int rc;
	int index = XSL_CTRL_ATT_HYSTERESIS_ENABLED - 1;
	rc = checkvalidity(n, XSL_CTRL_CMD_SET_HYSTERESIS, xsla, index);

	if (rc) {
			PERROR("Validity check failed\n");
			return rc;
	}

	if ( xsla[index]->rta_type != XSL_CTRL_ATT_HYSTERESIS_ENABLED) {
			PERROR("Invalid att %u\n", xsla[index]->rta_type);
			return -EINVAL;
	}
	val = *((int *)(RTA_DATA(xsla[index])));
	hysteresis_enabled = val ? 1 : 0;
    
    printk(KERN_INFO "QOS: hysteresis mode changed. value is %d.\n", hysteresis_enabled);

	return 0;
}

#ifdef MODULE
int init_otb_sch(void)
{
  DPRINTK("register otb_sch qdisc module \n");

  return register_qdisc(&otb_sch_qdisc_ops);
    
}

void cleanup_otb_sch(void) 
{
  DPRINTK("unregister otb_sch qdisc module\n");
  unregister_qdisc(&otb_sch_qdisc_ops);
}

#endif
