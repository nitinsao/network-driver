#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/icmp.h>         /* struct icmphdr */
#include <linux/skbuff.h>

#include <asm/checksum.h>

/* These are the flags in the statusword */
#define SN_RX_INTR 0x0001
#define SN_TX_INTR 0x0002

/* Default timeout period */
#define SN_TIMEOUT 5   /* In jiffies */


MODULE_AUTHOR("Simple Network Devlopers");
MODULE_LICENSE("Dual BSD/GPL");	

static int timeout = SN_TIMEOUT;

/*
 * The devices
 */
struct net_device *sn_devs;

int pool_size = 8;						// pool size for packets per dev
module_param(pool_size, int, 0);

// static void (*sn_interrupt)(int, void *, struct pt_regs *);

struct sn_packet {
	struct sn_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];			// ETH_DATA_LEN = 1500 octets (MTU)
};

struct sn_priv {
	struct net_device *dev;	
	struct napi_struct napi;
	struct net_device_stats stats;
	int status;
	struct sn_packet *ppool;	
	struct sn_packet *rx_queue;  /* List of incoming packets */
	int rx_int_enabled;
	int tx_packetlen;
	u8 *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
};


static void sn_rx_ints(struct net_device *dev, int enable)
{
	struct sn_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
	printk(KERN_ALERT "%s called", __FUNCTION__);
}

void sn_setup_pool(struct net_device *dev)
{
	struct sn_priv *priv = netdev_priv(dev);
	int i;
	struct sn_packet *pkt;

	priv->ppool = NULL;
	for (i = 0; i < pool_size; i++) {
		pkt = kmalloc (sizeof (struct sn_packet), GFP_KERNEL);
		if (pkt == NULL) {
			printk (KERN_NOTICE "Ran out of memory allocating packet pool\n");
			return;
		}
		pkt->dev = dev;
		pkt->next = priv->ppool;
		priv->ppool = pkt;
	}
}

int sn_open(struct net_device *dev)
{
	memcpy(dev->dev_addr, "\0SNUL0", ETH_ALEN);
	netif_start_queue(dev);
	return 0;
}

int sn_release(struct net_device *dev)
{
	netif_stop_queue(dev); /* can't transmit any more */
	return 0;
}

struct sn_packet *sn_get_tx_buffer(struct net_device *dev)
{
	struct sn_priv *priv = netdev_priv(dev);
	unsigned long flags;
	struct sn_packet *pkt;
    
	spin_lock_irqsave(&priv->lock, flags);
	pkt = priv->ppool;
	priv->ppool = pkt->next;
	if (priv->ppool == NULL) {
		printk (KERN_INFO "Pool empty\n");
		netif_stop_queue(dev);
	}
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

void sn_enqueue_buf(struct net_device *dev, struct sn_packet *pkt)
{
	unsigned long flags;
	struct sn_priv *priv = netdev_priv(dev);

	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->rx_queue;  /* FIXME - misorders packets */
	priv->rx_queue = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
}

void sn_rx(struct net_device *dev, struct sn_packet *pkt)
{
	struct sk_buff *skb;
	struct sn_priv *priv = netdev_priv(dev);

	skb = dev_alloc_skb(pkt->datalen + 2);
	if (!skb) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "sn rx: low on mem - packet dropped\n");
		priv->stats.rx_dropped++;
		goto out;
	}
	skb_reserve(skb, 2); /* align IP on 16B boundary */  
	memcpy(skb_put(skb, pkt->datalen), pkt->data, pkt->datalen);

	/* Write metadata, and then pass to the receive level */
	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += pkt->datalen;
	netif_rx(skb);
  out:
	return;
}

void sn_release_buffer(struct sn_packet *pkt)
{
	unsigned long flags;
	struct sn_priv *priv = netdev_priv(pkt->dev);
	
	spin_lock_irqsave(&priv->lock, flags);
	pkt->next = priv->ppool;
	priv->ppool = pkt;
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(pkt->dev) && pkt->next == NULL)
		netif_wake_queue(pkt->dev);
}

static void sn_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	int statusword;
	struct sn_priv *priv;
	struct sn_packet *pkt = NULL;
	

	struct net_device *dev = (struct net_device *)dev_id;
	

	if (!dev)
		return;

	/* Lock the device */
	priv = netdev_priv(dev);
	spin_lock(&priv->lock);

	/* retrieve statusword: real netdevices use I/O instructions */
	statusword = priv->status;
	priv->status = 0;
	if (statusword & SN_RX_INTR) {
		/* send it to sn_rx for handling */
		pkt = priv->rx_queue;
		if (pkt) {
			priv->rx_queue = pkt->next;
			sn_rx(dev, pkt);
		}
	}
	if (statusword & SN_TX_INTR) {
		/* a transmission is over: free the skb */
		priv->stats.tx_packets++;
		priv->stats.tx_bytes += priv->tx_packetlen;
		dev_kfree_skb(priv->skb);
	}

	/* Unlock the device and we are done */
	spin_unlock(&priv->lock);
	if (pkt) sn_release_buffer(pkt); /* Do this outside the lock! */
	return;
}

/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
unsigned short checksum(void *b, int len)
{	unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

static void sn_hw_tx(char *buf, int len, struct net_device *dev)
{
	struct iphdr *ih;
	struct net_device *dest;
	struct sn_priv *priv;
	u32 *saddr, *daddr;
	struct sn_packet *tx_buffer;
    

	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		printk("sn: Hmm... packet too short (%i octets)\n",
				len);
		return;
	}

	ih = (struct iphdr *)(buf+sizeof(struct ethhdr));
	saddr = &ih->saddr;
	daddr = &ih->daddr;

	printk(KERN_ALERT "src : %d.%d.%d.%d", ((u8 *)saddr)[0], ((u8 *)saddr)[1], ((u8 *)saddr)[2], ((u8 *)saddr)[3]);
	printk(KERN_ALERT "dest : %d.%d.%d.%d\n", ((u8 *)daddr)[0], ((u8 *)daddr)[1], ((u8 *)daddr)[2], ((u8 *)daddr)[3]);
	
	((u8 *)saddr)[3] ^= 3; /* change the fourth octet (class C) */
	((u8 *)daddr)[3] ^= 3;
	printk(KERN_ALERT "new src : %d.%d.%d.%d", ((u8 *)saddr)[0], ((u8 *)saddr)[1], ((u8 *)saddr)[2], ((u8 *)saddr)[3]);
	printk(KERN_ALERT "new dest : %d.%d.%d.%d\n\n", ((u8 *)daddr)[0], ((u8 *)daddr)[1], ((u8 *)daddr)[2], ((u8 *)daddr)[3]);
	
	if(ih->protocol == IPPROTO_ICMP)	// (ICMP = 1, TCP = 6, UDP = 17)
	{
		// struct icmphdr *icmp = (struct icmphdr*) (buf+ sizeof(struct iphdr) + sizeof(struct ethhdr));

		priv = netdev_priv(dev);
		struct icmphdr *icmp = icmp_hdr(priv->skb);
		if(icmp->type == ICMP_ECHO)
		{
			printk(KERN_ALERT "****ICMP Echo Header****");
			printk(KERN_ALERT "type: %d, code: %d, checksum: %d", icmp->type, icmp->code, ntohs(icmp->checksum));
			printk(KERN_ALERT "echo.id: %d, echo.seq: %d", icmp->un.echo.id, icmp->un.echo.sequence);
			icmp->checksum = 0;
			printk(KERN_ALERT "Before changing, checksum: %d", checksum(icmp, sizeof(struct icmphdr)));
			icmp->type = ICMP_ECHOREPLY;
			// icmp->checksum += 0x0800;	// Combination of type and code
			// icmp->checksum = checksum(icmp, ETH_DATA_LEN - dev->hard_header_len /*Ethernet*/ - ih->ihl /*IP*/);

			printk(KERN_ALERT "Now ICMP Echo reply, \ntype: %d, code: %d, checksum: %d", icmp->type, icmp->code, ntohs(icmp->checksum));
			printk(KERN_ALERT "echo.id: %d, echo.seq: %d", icmp->un.echo.id, icmp->un.echo.sequence);
			printk(KERN_ALERT "**********");
		}
	}

	ih->check = 0;         /* and rebuild the checksum (ip needs it) */
	ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);


	dest = dev;
	priv = netdev_priv(dest);
	tx_buffer = sn_get_tx_buffer(dev);
	tx_buffer->datalen = len;
	memcpy(tx_buffer->data, buf, len);
	sn_enqueue_buf(dest, tx_buffer);
	if (priv->rx_int_enabled) {
		priv->status |= SN_RX_INTR;
		sn_interrupt(0, dest, NULL);
	}

	priv = netdev_priv(dev);
	priv->tx_packetlen = len;
	priv->tx_packetdata = buf;
	priv->status |= SN_TX_INTR;
	
		sn_interrupt(0, dev, NULL);
}

int sn_tx(struct sk_buff *skb, struct net_device *dev)
{
	int len;
	char *data, shortpkt[ETH_ZLEN];
	struct sn_priv *priv = netdev_priv(dev);
	
	data = skb->data;
	len = skb->len;
	if (len < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, skb->data, skb->len);
		len = ETH_ZLEN;
		data = shortpkt;
	}

	/* Remember the skb, so we can free it at interrupt time */
	priv->skb = skb;

	/* actual deliver of data is device-specific, and not shown here */
	sn_hw_tx(data, len, dev);

	return 0; /* Our simple device can not fail */
}

void sn_tx_timeout (struct net_device *dev)
{
	struct sn_priv *priv = netdev_priv(dev);

	/* Simulate a transmission interrupt to get things moving */
	priv->status = SN_TX_INTR;
	sn_interrupt(0, dev, NULL);
	priv->stats.tx_errors++;
	netif_wake_queue(dev);
	return;
}

struct net_device_stats *sn_stats(struct net_device *dev)
{
	struct sn_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

int sn_config(struct net_device *dev, struct ifmap *map)
{
	if (dev->flags & IFF_UP) /* can't act on a running interface */
		return -EBUSY;

	/* Don't allow changing the I/O address */
	if (map->base_addr != dev->base_addr) {
		printk(KERN_WARNING "sn: Can't change I/O address\n");
		return -EOPNOTSUPP;
	}

	/* Allow changing the IRQ */
	if (map->irq != dev->irq) {
		dev->irq = map->irq;
        	/* request_irq() is delayed to open-time */
	}

	/* ignore other fields */
	return 0;
}

int sn_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	printk(KERN_ALERT "ioctl\n");
	return 0;
}

static const struct net_device_ops sn_netdev_ops = {
	.ndo_open		= sn_open,
	.ndo_stop		= sn_release,
	.ndo_set_config		= sn_config,
	.ndo_start_xmit		= sn_tx,
	.ndo_do_ioctl		= sn_ioctl,
	.ndo_get_stats		= sn_stats,
	.ndo_tx_timeout         = sn_tx_timeout,
};

int sn_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned len)
{
	struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);

	eth->h_proto = htons(type);
	memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
	memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);
	eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return (dev->hard_header_len);
}

static const struct header_ops sn_header_ops = {
	.create 	= sn_header,
	.cache 		= NULL,
};

void sn_init(struct net_device *dev)
{
	struct sn_priv *priv;

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct sn_priv));
	spin_lock_init(&priv->lock);
	priv->dev = dev;


	ether_setup(dev); /* assign some of the fields */

	dev->watchdog_timeo = timeout;
	

	/* keep the default flags, just add NOARP */
	dev->flags           |= IFF_NOARP;// | IFF_ECHO;
	dev->features        |= NETIF_F_HW_CSUM;
	dev->netdev_ops = &sn_netdev_ops;
	dev->header_ops = &sn_header_ops;

	sn_rx_ints(dev, 1);		/* enable receive interrupts */
	sn_setup_pool(dev);
}

void sn_cleanup(void);

int sn_init_module(void)
{
	int result, ret = -ENOMEM;



	/* Allocate the devices */
	sn_devs = alloc_netdev(sizeof(struct sn_priv), "sn", NET_NAME_UNKNOWN,
			sn_init);
	
	if (sn_devs == NULL)
		goto out;

	ret = -ENODEV;
	if ((result = register_netdev(sn_devs)))
		printk("sn: error %i registering device \"%s\"\n",
				result, sn_devs->name);
	else
		ret = 0;
   out:
	if (ret) 
		sn_cleanup();
	return ret;
}

void sn_teardown_pool(struct net_device *dev)
{
	struct sn_priv *priv = netdev_priv(dev);
	struct sn_packet *pkt;
    
	while ((pkt = priv->ppool)) {
		priv->ppool = pkt->next;
		kfree (pkt);
	}
}    

void sn_cleanup(void)
{
	if (sn_devs) {
		unregister_netdev(sn_devs);
		sn_teardown_pool(sn_devs);
		free_netdev(sn_devs);
	}
	return;
}


module_init(sn_init_module);
module_exit(sn_cleanup);
