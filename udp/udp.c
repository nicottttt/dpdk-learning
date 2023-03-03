#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include "arp.h"
#include <arpa/inet.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#define NUM_MBUFS (4096-1)
#define ENABLE_SEND 1
#define ENABLE_ARP 1
#define ENABLE_ICMP 1
#define ENABLE_ARP_REPLY 1
#define ENABLE_DEBUG 1
#define ENABLE_TIMER 1
#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6 
#define ENABLE_RINGBUFFER 1
#define RING_SIZE 1024
#define ENABLE_MULTITHREAD 1
#define BURST_SIZE	32
#define ENABLE_UDP_APP 1
#define UDP_APP_RECV_BUFFER_SIZE 128

#if ENABLE_SEND
//ip,mac,port
//define it as a global para means that only allow one client
#define MAKDE_IPV4_ADDR(a,b,c,d) (a+(b<<8)+(c<<16)+(d<<24))//ipadress

static uint32_t gLocalIp=MAKDE_IPV4_ADDR(129,104,95,11);

static uint32_t gSrcIp;
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;
static uint16_t gDstPort;
#endif

#if ENABLE_ARP_REPLY

static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#endif

//
#if ENABLE_RINGBUFFER
struct inout_ring{
	struct rte_ring *inring;
	struct rte_ring *outring;
};

static struct inout_ring *rInst=NULL;

//initialize
static struct inout_ring *ringInstance(void){
	if(rInst==NULL){
		rInst=rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
		memset(rInst, 0, sizeof(struct inout_ring));
	}
	return rInst;
}

#endif


int gDpdkPortId=0;

static const struct rte_eth_conf port_conf_default={
	.rxmode={.max_rx_pkt_len=RTE_ETHER_MAX_LEN}
};

static void ng_init_port(struct rte_mempool *mbuf_pool){//initialize
	uint16_t nb_sys_ports=rte_eth_dev_count_avail();
	if(nb_sys_ports==0){
		rte_exit(EXIT_FAILURE,"No support\n");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);

	const int num_rx_qeues=1;
	const int num_tx_qeues=1;

	struct rte_eth_conf port_conf=port_conf_default;
	
	//write the configuration
	rte_eth_dev_configure(gDpdkPortId, num_rx_qeues, num_tx_qeues, &port_conf);
	//set rx queue
	if(rte_eth_rx_queue_setup(gDpdkPortId,0, 1024, rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool)<0){
		rte_exit(EXIT_FAILURE,"Could not setup RX queue\n");
	}

#if ENABLE_SEND
	//set tx queue
	struct rte_eth_txconf txq_conf=dev_info.default_txconf;
	txq_conf.offloads= port_conf.rxmode.offloads;//send and receive have the same size
	if(rte_eth_tx_queue_setup(gDpdkPortId,0, 1024, rte_eth_dev_socket_id(gDpdkPortId),&txq_conf)<0){
		rte_exit(EXIT_FAILURE,"Could not setup TX queue\n");
	}
#endif

	if(rte_eth_dev_start(gDpdkPortId)<0){
		rte_exit(EXIT_FAILURE,"Could not start\n");
	}
	rte_eth_promiscuous_enable(gDpdkPortId);

};

#if ENABLE_SEND

static int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {

	// encode 

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = gSrcIp;
	ip->dst_addr = gDstIp;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = gSrcPort;
	udp->dst_port = gDstPort;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udp+1), data, udplen);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	struct in_addr addr;
	addr.s_addr = gSrcIp;
	printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort));

	addr.s_addr = gDstIp;
	printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));

	return 0;
}

//send msg(after receiving)
//the procedure is to package the udp pkt first, and then return the mbuf, and finally send by the function burst.
static struct rte_mbuf *udp_send(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length){
	//mempool-->mbuf
	const unsigned total_len= length+14+20+8;//data length+eht_hdr+ip_hdr+udp_hdr
	struct rte_mbuf *mbuf=rte_pktmbuf_alloc(mbuf_pool);//set the starting point of the mbuf
	if(!mbuf){
		rte_exit(EXIT_FAILURE,"alloc wrong\n");
	}
	mbuf->pkt_len=total_len;
	mbuf->data_len=total_len;

	uint8_t *pktdata= rte_pktmbuf_mtod(mbuf, uint8_t*);
	ng_encode_udp_pkt(pktdata,data,total_len);//package it to udp pkt
	return mbuf;
}

#endif

#if ENABLE_ARP

static int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode,uint8_t *dst_mac, uint32_t sip, uint32_t dip){
	//it is a network layer protocol, includes ether hdr, arp hdr

	//if dont know where to send, the arphdr(dst_mac) will be FFFFFFFF and the machdr will be 00000000, it is differendt!!!!

	//etherhdr:
	struct rte_ether_hdr *eth=(struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	if (!strncmp((const char *)dst_mac, (const char *)gDefaultArpMac, RTE_ETHER_ADDR_LEN)) {
		uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};//00000000
		rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	//arp hdr:
	struct rte_arp_hdr *arp=(struct rte_arp_hdr *)(eth+1);
	arp->arp_hardware=htons(1);
	arp->arp_protocol=htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen=RTE_ETHER_ADDR_LEN;
	arp->arp_plen=sizeof(uint32_t);
	arp->arp_opcode=htons(opcode);
	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	arp->arp_data.arp_sip=sip;
	arp->arp_data.arp_tip=dip;

	return 0;
}

static struct rte_mbuf *arp_send(struct rte_mempool *mbuf_pool, uint16_t opcode,uint8_t *dst_mac,uint32_t sip,uint32_t dip){
	const unsigned total_length=sizeof(struct rte_ether_hdr)+sizeof(struct rte_arp_hdr);//14+28
	//allocate some mem for the buf
	struct rte_mbuf *mbuf=rte_pktmbuf_alloc(mbuf_pool);
	if(!mbuf){
		rte_exit(EXIT_FAILURE,"Allocate memory wrong\n");
	}

	mbuf->pkt_len=total_length;
	mbuf->data_len=total_length;

	uint8_t *pkt_data=rte_pktmbuf_mtod(mbuf,uint8_t *);
	ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

	return mbuf;

}

#endif

#if ENABLE_ICMP

//cksum for icmp
static uint16_t ng_checksum(uint16_t *addr, int count) {

	register long sum = 0;

	while (count > 1) {

		sum += *(unsigned short*)addr++;
		count -= 2;
	
	}

	if (count > 0) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}


static int ng_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip,uint16_t id,uint16_t seqnum){
	//it is an transportation layer protocol, include 3 header: ether, ip, icmp

	//ether hdr
	struct rte_ether_hdr *eth=(struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type=htons(RTE_ETHER_TYPE_IPV4);//define the network layer protocol

	//ip hdr
	struct rte_ipv4_hdr *ip=(struct rte_ipv4_hdr *)(msg+sizeof(struct rte_ether_hdr));//set the offset
	ip->version_ihl= 0x45;
	ip->type_of_service= 0;
	ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	ip->packet_id=0;
	ip->fragment_offset=0;
	ip->time_to_live=64;//default value is 64
	ip->next_proto_id=IPPROTO_ICMP;//define the application layer protocol
	ip->src_addr=sip;
	ip->dst_addr=dip;
	ip->hdr_checksum=0;//first set to 0
	ip->hdr_checksum=rte_ipv4_cksum(ip);


	//icmp hdr
	struct rte_icmp_hdr *icmp=(struct rte_icmp_hdr *)(msg+sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv4_hdr));//offset the ether header and the ip header
	icmp->icmp_type=RTE_IP_ICMP_ECHO_REPLY;
	icmp->icmp_code=0;
	icmp->icmp_ident=id;
	icmp->icmp_seq_nb= seqnum;
	icmp->icmp_cksum=0;
	icmp->icmp_cksum = ng_checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr));
	return 0;
}


static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool,uint8_t *dst_mac,uint32_t sip,uint32_t dip,uint16_t id,uint16_t seqnum){
	const unsigned total_length=sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv4_hdr)+sizeof(struct rte_icmp_hdr);
	//allocate some mem for the buf
	struct rte_mbuf *mbuf=rte_pktmbuf_alloc(mbuf_pool);
	if(!mbuf){
		rte_exit(EXIT_FAILURE,"Allocate memory wrong\n");
	}
	
	mbuf->pkt_len=total_length;
	mbuf->data_len=total_length;

	uint8_t *pkt_data=rte_pktmbuf_mtod(mbuf,uint8_t *);
	ng_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnum);

	return mbuf;

}

#endif

// print ethernet mac adress
static void print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}


#if ENABLE_TIMER

static void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg) {

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring=ringInstance();
#if 0
	struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, ahdr->arp_data.arp_sha.addr_bytes, ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
	rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
	rte_pktmbuf_free(arpbuf);

#endif
	
	int i = 0;
	//send to every machine link to this local network
	for (i = 1;i <= 254;i ++) {

		uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));

		//print arp msg
		struct in_addr addr;
		addr.s_addr = dstip;
		printf("arp ---> src: %s \n", inet_ntoa(addr));

		struct rte_mbuf *arpbuf = NULL;
		uint8_t *dstmac = ng_get_dst_macaddr(dstip);
		if (dstmac == NULL) {

			//arphdr:FFFFFFFF
			//machdr:00000000 !!!!!
			arpbuf = arp_send(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);
		
		} else {

			arpbuf = arp_send(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
		}

		// rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
		// rte_pktmbuf_free(arpbuf);
		rte_ring_mp_enqueue_burst(ring->outring, (void**)&arpbuf , 1, NULL); 
		
	}
	
}


#endif



#if ENABLE_MULTITHREAD

#if ENABLE_UDP_APP

struct localhost{

	int fd;
	//unsigned int status;
	uint32_t localip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;
	int protocol;

	struct rte_ring *sndbuffer;
	struct rte_ring *rcvbuffer;

	struct localhost *prev;
	struct localhost *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};

static struct localhost *lhost=NULL;

#define DEFAULT_FD_NUM 3

static int get_fd_frombitmap(void) {
	int fd = DEFAULT_FD_NUM;
	return fd;
}

static struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto) {

	struct localhost *host;

	for (host = lhost; host != NULL;host = host->next) {
		if (dip == host->localip && port == host->localport && proto == host->protocol) {
			return host;
		}
	}
	return NULL;
	
}

static int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	unsigned char *data, uint16_t total_len) {

	// encode 

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = sport;
	udp->dst_port = dport;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udp+1), data, udplen);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	return 0;
}

static struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac, uint8_t *data, uint16_t length) {

	// mempool --> mbuf

	const unsigned total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac, data, total_len);

	return mbuf;

}

struct offload{//udp packet

	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint8_t protocol;
	unsigned char *data;
	uint16_t length;

};

static int udp_process(struct rte_mbuf *udpmbuf){

	struct rte_ipv4_hdr *iphdr=rte_pktmbuf_mtod_offset(udpmbuf ,struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));//get the ip hdr
	struct rte_udp_hdr *udphdr=(struct rte_udp_hdr *)(iphdr+1);//get the udp hdr,从iphdr开始偏移iphdr的长度

	struct localhost *host=get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id );
	if(host==NULL){//if dont find, just exit  
		rte_pktmbuf_free(udpmbuf);
		return -3; 
	}

	struct offload *ol=rte_malloc("offload", sizeof(struct offload),0);
	if(ol==NULL){
		rte_pktmbuf_free(udpmbuf);
		return -1;
	}

	ol->dip=iphdr->dst_addr;
	ol->sip=iphdr->src_addr;
	ol->dport=udphdr->dst_port;
	ol->sport=udphdr->src_port;
	ol->protocol=IPPROTO_UDP;
	ol->length=ntohs(udphdr->dgram_len);

	ol->data=rte_malloc("unsigned cahr*", ol->length -sizeof(struct rte_udp_hdr),0);
	if(ol->data==NULL){
		rte_pktmbuf_free(udpmbuf);
		rte_free(ol);
		return -2;
	}

	rte_memcpy(ol->data, (unsigned char *)(udphdr+1), ol->length - sizeof(struct rte_udp_hdr));
	rte_ring_mp_enqueue(host->rcvbuffer, ol);//push into the udp server recv buffer 

	//wake the thread here after enqueue some elements in the queue
	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);

	rte_pktmbuf_free(udpmbuf);
	return 0;

}

//offload--->mbufs
static int udp_out(struct rte_mempool *mbuf_pool){

	struct localhost *host;
	for (host = lhost; host != NULL; host = host->next) {

		struct offload *ol;
		int nb_snd = rte_ring_mc_dequeue(host->sndbuffer, (void **)&ol);
		if (nb_snd < 0) continue;

		struct in_addr addr;
		addr.s_addr = ol->dip;
		printf("udp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
			
		uint8_t *dstmac = ng_get_dst_macaddr(ol->dip);
		if (dstmac == NULL) {//if there is no mac adress in arp table, send an arp request

			struct rte_mbuf *arpbuf = arp_send(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, ol->sip, ol->dip);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->outring, (void **)&arpbuf, 1, NULL);//put the arp msg into the out ring buffer

			rte_ring_mp_enqueue(host->sndbuffer, ol);//here put the msg back to the snd buffer because we must send the arp msg first and get the mac adress
			
		} else {
			//package an udp pkt
			struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport, host->localmac, dstmac, ol->data, ol->length);
			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->outring, (void **)&udpbuf, 1, NULL);//put the udp pkt into the out ring buffer

		}
		
	}

	return 0;

}


#endif

static int pkt_process(void *arg) {

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring=ringInstance();  
	while(1){

		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->inring, (void**)mbufs, BURST_SIZE, NULL);//pop the msg in the ring buffer


		//analyze the pkt
		unsigned i=0;
		for(i=0;i<num_recvd;i++){
			struct rte_ether_hdr *ehdr=rte_pktmbuf_mtod(mbufs[i],struct rte_ether_hdr*);//analyze the ethernet header

#if ENABLE_ARP
			if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)){
				struct rte_arp_hdr *ahdr=rte_pktmbuf_mtod_offset(mbufs[i],struct rte_arp_hdr *,sizeof(struct rte_ether_hdr));//offset the header of ethernet

				// struct in_addr addr;
				// addr.s_addr=gLocalIp;
				// printf("local----->: %s\n, ",inet_ntoa(addr));

				if(ahdr->arp_data.arp_tip==gLocalIp){//only response to the host ip

					if(ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)){//deal with arp request msg
						struct in_addr addr;
						addr.s_addr=ahdr->arp_data.arp_tip;
						printf("arp---request>: %s\n ",inet_ntoa(addr));

						struct rte_mbuf *arpbuf= arp_send(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes, ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
						rte_ring_mp_enqueue_burst(ring->outring, (void**)&arpbuf, 1, NULL); 
						rte_pktmbuf_free(arpbuf);
						
					}else if(ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)){//receive arp repley msg, put the adress into the arp table
						
						printf("arp --> reply\n");

						struct arp_table *table = arp_table_instance();
						uint8_t *hwaddr = ng_get_dst_macaddr(ahdr->arp_data.arp_sip);
						if (hwaddr == NULL) {

							struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
							if (entry) {
								memset(entry, 0, sizeof(struct arp_entry));

								entry->ip = ahdr->arp_data.arp_sip;
								rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
								entry->type = 0;
								
								LL_ADD(entry, table->entries);
								table->count ++;
							}

						}

						
#if ENABLE_DEBUG
						struct arp_entry *iter;
						for (iter = table->entries; iter != NULL; iter = iter->next) {
							struct in_addr addr;
							addr.s_addr = iter->ip;
							print_ethaddr("arp table --> mac: ", (struct rte_ether_addr *)iter->hwaddr);
							printf(" ip: %s \n", inet_ntoa(addr));
					
						}
#endif
						rte_pktmbuf_free(mbufs[i]);

					}// end if it is request or repley arp msg

				}//end if if(ahdr->arp_data.arp_tip=...

				continue;
			}//end if(ehdr->ether_type....
#endif

//udp
			if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
				rte_pktmbuf_free(mbufs[i]);
				continue;//if not ipv4,then skip
			}
			
			struct rte_ipv4_hdr *iphdr=rte_pktmbuf_mtod_offset(mbufs[i],struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));//get the ip hdr

			//udp
			if(iphdr->next_proto_id==IPPROTO_UDP){
				
				udp_process(mbufs[i]);

			}//udp if end
			
#if ENABLE_ICMP//icmp is on the same layer of udp

			if(iphdr->next_proto_id==IPPROTO_ICMP){//icmp
				struct rte_icmp_hdr *icmphdr=(struct rte_icmp_hdr *)(iphdr + 1);
				if(icmphdr->icmp_type==RTE_IP_ICMP_ECHO_REQUEST){
					//print the msg:
					printf("Get the icmp pkt:\n");
					struct in_addr addr;
					addr.s_addr=iphdr->src_addr;
					printf("icmp:src----->: %s ",inet_ntoa(addr));
					addr.s_addr=iphdr->dst_addr;
					printf("icmp:dst----->: %s\n",inet_ntoa(addr));
					
					struct rte_mbuf *txbuf=ng_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes, iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
					rte_ring_mp_enqueue_burst(ring->outring, (void**)&txbuf, 1, NULL);  

					rte_pktmbuf_free(mbufs[i]);
				}

			}//icmp if end

#endif
		}// for end

#if ENABLE_UDP_APP

	udp_out(mbuf_pool);

#endif


	}//while 1 end

	return 0;

}

#endif


#if ENABLE_UDP_APP



static struct localhost * get_hostinfo_fromfd(int sockfd){

	struct localhost *host;
	for(host=lhost;host!=NULL;host=host->next){
		if(sockfd==host->fd){
			return host;//bind the local var host to one element of the global lhost
		}
	}
	
	return NULL;

}




static int nico_socket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol){
	//distribute a fd and link a type to the socket

	int fd=get_fd_frombitmap();
	struct localhost *host = rte_malloc("localhost", sizeof (struct localhost),0);
	if(host == NULL){
		return -1;
	}

	memset(host, 0, sizeof(struct localhost));

	host->fd=fd;
	if(type==SOCK_DGRAM){
		host->protocol=IPPROTO_UDP;
	}
	// else if(type==SOCK_STGREAM){
	// 	host->protocol=IPPROTO_TCP; 
	// }

	//create receive buffer
	host->rcvbuffer=rte_ring_create("recv buffer", RING_SIZE,rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
	if(host->rcvbuffer==NULL){
		rte_free(host);
		return -1;
	}

	//create send buffer
	host->sndbuffer=rte_ring_create("send buffer", RING_SIZE,rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
	if(host->sndbuffer==NULL){
		rte_ring_free(host->rcvbuffer);
		rte_free(host);
		return -1;
	}

	pthread_cond_t blank_cond=PTHREAD_COND_INITIALIZER;
	rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex=PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&host->cond, &blank_mutex, sizeof(pthread_mutex_t));


	LL_ADD(host, lhost); 

	return fd;

}

static int nico_bind(int sockfd, const struct sockaddr *addr, __attribute__((unused)) socklen_t addrlen){
	//bind the port, ipaddres and macadress
	struct localhost *host = get_hostinfo_fromfd(sockfd);//find the host through the fd
	if(host == NULL)return -1;

	//bind here
	const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
	host->localport = laddr->sin_port;
	rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
	rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	return 0;
}

static ssize_t nico_recvfrom(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags, struct sockaddr *src_addr, __attribute__((unused)) socklen_t *addrlen){
	struct localhost *host=get_hostinfo_fromfd(sockfd);
	if(host==NULL)return -1;

	unsigned char *ptr=NULL;
	struct offload *ol=NULL;
	int nb=-1;

	//set mutex in the thread
	pthread_mutex_lock(&host->mutex);
	while((nb = rte_ring_mc_dequeue(host->rcvbuffer,(void **)&ol))<0){//take the offload from the recvbuffer
		pthread_cond_wait(&host->cond, &host->mutex);
	}
	pthread_mutex_unlock(&host->mutex);

	struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
	saddr->sin_port = ol->sport;
	rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

	if(len<ol->length){
		rte_memcpy(buf, ol->data, len);
		//malloc a new place to the data that we haven't take
		ptr=rte_malloc("unsigned char", ol->length, 0);
		rte_memcpy(ptr, ol->data+len, ol->length-len);
		ol->length-=len;
		rte_free(ol->data);
		ol->data=ptr;

		//enqueue the data that exceed the len:
		rte_ring_mp_enqueue(host->rcvbuffer, ol);
		return len;
	}else{
		
		rte_memcpy(buf, ol->data, ol->length);
		//printf("into here: ol->data------>%s\n",ol->data);
		rte_free(ol->data);
		rte_free(ol);
		return ol->length;
	}

}

static ssize_t nico_sendto(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags, const struct sockaddr *dest_addr, __attribute__((unused)) socklen_t addrlen){


	struct localhost *host=get_hostinfo_fromfd(sockfd);
	if(host==NULL)return -1;

	const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

	struct offload *ol=rte_malloc("offload", sizeof(struct offload), 0);
	if(ol==NULL) return -1;

	ol->dip=daddr->sin_addr.s_addr;
	ol->dport=daddr->sin_port;
	ol->sip=host->localip;
	ol->sport=host->localport;
	ol->length=len;
	ol->data=rte_malloc("unsigned char*", len, 0);
	if(ol->data==NULL){
		rte_free(ol);
		return -1;
	}

	rte_memcpy(ol->data, buf, len);

	rte_ring_mp_enqueue(host->sndbuffer, ol);

	return len;



}


static int nico_close(int fd){

	struct localhost *host = get_hostinfo_fromfd(fd);//find the fd through host
	if(host == NULL)return -1;

	LL_REMOVE(host, lhost);
	if(host->rcvbuffer){
		rte_ring_free(host->rcvbuffer);	
	}
	if(host->sndbuffer){
		rte_ring_free(host->sndbuffer);	
	}
	rte_free(host);

}


//create a udp server:
static int udp_server_entry(__attribute__((unused))  void *arg) {

	//create a socket
	int connfd = nico_socket(AF_INET, SOCK_DGRAM, 0);
	if (connfd == -1) {
		printf("sockfd failed\n");
		return -1;
	} 

	struct sockaddr_in localaddr, clientaddr; // struct sockaddr 
	memset(&localaddr, 0, sizeof(struct sockaddr_in));

	//bind port and ip adress
	localaddr.sin_port = htons(8888);
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = inet_addr("129.104.95.11"); 
	nico_bind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

	char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
	socklen_t addrlen = sizeof(clientaddr);
	while (1) {

		if (
			//nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, (struct sockaddr*)&clientaddr, &addrlen) < 0
			nico_recvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, (struct sockaddr*)&clientaddr, &addrlen) < 0
			) {

			continue;

		} else {

			printf("recv from %s:%d, data:%s\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), buffer);
			//nsendto(connfd, buffer, strlen(buffer), 0, (struct sockaddr*)&clientaddr, sizeof(clientaddr));
			nico_sendto(connfd, buffer, strlen(buffer), 0, (struct sockaddr*)&clientaddr, sizeof(clientaddr));
		}

	}

	nico_close(connfd);

}


#endif



int main(int argc, char*argv[]){
	if(rte_eal_init(argc,argv)<0){
		rte_exit(EXIT_FAILURE,"Error with EAL init\n");
	}
	
	struct rte_mempool *mbuf_pool=rte_pktmbuf_pool_create("mbuf pool",NUM_MBUFS,0,0,RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if(mbuf_pool==NULL){
		rte_exit(EXIT_FAILURE,"Cloud not create mbuf\n");
	}
	ng_init_port(mbuf_pool);//initialize the port(eth0)

	rte_eth_macaddr_get(gDpdkPortId,(struct rte_ether_addr *)gSrcMac);


//setup a timer:
#if ENABLE_TIMER

	rte_timer_subsystem_init();

	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);//PERIODICAL: multiply trigger the timer

#endif


#if ENABLE_RINGBUFFER
	struct inout_ring *ring=ringInstance();
	if(ring==NULL){rte_exit(EXIT_FAILURE,"ring init fail\n");}

	if(ring->inring==NULL){
		ring->inring=rte_ring_create("in ring", RING_SIZE,rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
	}

	if(ring->outring==NULL){
		ring->outring=rte_ring_create("out ring", RING_SIZE,rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
	}	

#endif

#if ENABLE_MULTITHREAD

	//启动线程，和cpu粘合的
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);

#endif


#if ENABLE_UDP_APP
	
	//启动线程，和cpu粘合的
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);//bind another core
	rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);

#endif

//up to here, establish 3 thread, which are: main thread, thread for the protocol analyze and thread for udp server

	while(1){
		
		//rx
		//Parse the application layer package
		struct rte_mbuf *rx[32];
		unsigned num_recvd=rte_eth_rx_burst(gDpdkPortId, 0, rx, 32);//receive msg 
		if(num_recvd>32){	
			rte_exit(EXIT_FAILURE,"Cloud not create mbuf\n");
		}
		else if(num_recvd>0){
			rte_ring_sp_enqueue_burst(ring->inring, (void**)rx, num_recvd, NULL);//receive msg and push into the ring buffer
		}


		//tx
		struct rte_mbuf *tx[32];
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->outring, (void**)tx, BURST_SIZE, NULL);//dequeue the msg and send through the network card
		if(nb_tx > 0){
			rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);//send out
			//release the memory
			unsigned i=0;
			for(i=0;i<nb_tx;i++){
				rte_pktmbuf_free(tx[i]);
			}
		}

#if ENABLE_TIMER

		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}

#endif

	}//while 1 end

}//main end
