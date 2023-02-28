#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "arp.h"
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

#if ENABLE_SEND
//ip,mac,port
//define it as a global para means that only allow one client
#define MAKDE_IPV4_ADDR(a,b,c,d) (a+(b<<8)+(c<<16)+(d<<24))

static uint32_t gLocalIp=MAKDE_IPV4_ADDR(129,104,95,11);
//static uint32_t gLocalIp=MAKDE_IPV4_ADDR(192,168,130,130);

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

#if ENABLE_RINGBUFFER
struct inout_ring{
	struct rte_ring *inring;
	struct rte_ring *outring;
};

static struct inout_ring *rInst=NULL;

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
static int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len){
	//etherhdr:
	struct rte_ether_hdr *eth=(struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type=htons(RTE_ETHER_TYPE_IPV4);

	//iphdr:
	struct rte_ipv4_hdr *ip=(struct rte_ipv4_hdr *)(msg+sizeof(struct rte_ether_hdr));//set the offset
	ip->version_ihl= 0x45;
	ip->type_of_service= 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id=0;
	ip->fragment_offset=0;
	ip->time_to_live=64;//default value is 64
	ip->next_proto_id=IPPROTO_UDP;
	ip->src_addr=gSrcIp;
	ip->dst_addr=gDstIp;
	ip->hdr_checksum=0;//first set to 0
	ip->hdr_checksum=rte_ipv4_cksum(ip);

	//udphdr:
	struct rte_udp_hdr *udp=(struct rte_udp_hdr *)(msg+sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv4_hdr));
	udp->src_port=gSrcPort;
	udp->dst_port=gDstPort;
	uint16_t udplen=total_len-sizeof(struct rte_ether_hdr)-sizeof(struct rte_ipv4_hdr);
	udp->dgram_len=htons(udplen);
	rte_memcpy((uint8_t*)(udp+1),data,udplen);//udp+1, go to the data part
	udp->dgram_cksum=0;
	udp->dgram_cksum=rte_ipv4_udptcp_cksum(ip,udp);

	// to check the code:
	// struct in_addr addr;
	// addr.s_addr=gSrcIp;
	// printf("-->src: %s:%d, ",inet_ntoa(addr),ntohs(gSrcPort));
	// addr.s_addr=gDstIp;
	// printf("dst: %s:%d\n ",inet_ntoa(addr),ntohs(gDstPort));

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
	struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, ahdr->arp_data.arp_sha.addr_bytes, 
		ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

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

static int pkt_process(void *arg) {

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring=ringInstance();  
	while(1){

		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->inring, (void**)mbufs, BURST_SIZE, NULL);


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

					if(ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)){//deal with request msg
						struct in_addr addr;
						addr.s_addr=ahdr->arp_data.arp_tip;
						printf("arp---request>: %s\n ",inet_ntoa(addr));

						struct rte_mbuf *arpbuf= arp_send(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes, ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
						rte_ring_mp_enqueue_burst(ring->outring, (void**)&arpbuf, 1, NULL); 
						rte_pktmbuf_free(arpbuf);
						
					}else if(ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)){//receive repley msg, put the adress into the arp table
						
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


			if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
				rte_pktmbuf_free(mbufs[i]);
				continue;//if not ipv4,then skip
			}
			
			struct rte_ipv4_hdr *iphdr=rte_pktmbuf_mtod_offset(mbufs[i],struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));//get the ip hdr

			//udp
			if(iphdr->next_proto_id==IPPROTO_UDP){
				struct rte_udp_hdr *udphdr=(struct rte_udp_hdr *)((unsigned char*)iphdr+sizeof(struct rte_ipv4_hdr));//get the udp hdr,从iphdr开始偏移iphdr的长度
				//printf("analyze the hdr of udp\n");


//to do a filter to get the msg from the port 8080
if(ntohs(udphdr->src_port)==8888){//ntohs!!!!!! it act as a filter,两个字节以上就要进行转换,htons:host to the network; ntohs: network to the host


#if ENABLE_SEND
				rte_memcpy( gDstMac,ehdr->s_addr.addr_bytes,RTE_ETHER_ADDR_LEN);//the s_addr of the package is where we want to send, so put it as dst addr
				rte_memcpy( &gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));//32 bits iphdr
				rte_memcpy( &gDstIp, &iphdr->src_addr, sizeof(uint32_t));
				rte_memcpy( &gSrcPort, &udphdr->dst_port, sizeof(uint16_t));//16 bits udphdr
				rte_memcpy( &gDstPort, &udphdr->src_port, sizeof(uint16_t));
#endif

				//receive the udp pkt and print it
				uint16_t length=ntohs(udphdr->dgram_len);
				*((char*)udphdr+length)='\0';
				//print
				printf("Start receiving and send back:\n");
				struct in_addr addr;
				addr.s_addr=iphdr->src_addr;
				printf("src: %s:%d, ",inet_ntoa(addr),ntohs(udphdr->src_port));
				addr.s_addr=iphdr->dst_addr;
				printf("dst: %s:%d, length:%d --> %s\n",inet_ntoa(addr),ntohs(udphdr->dst_port),length,(char *)(udphdr+1));
								
#if ENABLE_SEND//send back to where it comes from
					struct rte_mbuf *txbuf=udp_send(mbuf_pool,(uint8_t *)(udphdr+1),length);//udp +1, skip the udp header, directly to the data(payload)
					rte_ring_mp_enqueue_burst(ring->outring, (void**)&txbuf, 1, NULL); 
					 
#endif
			rte_pktmbuf_free(mbufs[i]);
}//only allow the msg from 8080 pass

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


	}//while 1 end

	return 0;

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
	rte_eal_remote_launch(pkt_process, mbuf_pool, rte_get_next_lcore(lcore_id, 1, 0));

#endif

	while(1){
		
		//rx
		//Parse the application layer package
		struct rte_mbuf *rx[32];
		unsigned num_recvd=rte_eth_rx_burst(gDpdkPortId, 0, rx, 32);//receive msg 
		if(num_recvd>32){	
			rte_exit(EXIT_FAILURE,"Cloud not create mbuf\n");
		}
		else if(num_recvd>0){
			rte_ring_sp_enqueue_burst(ring->inring, (void**)rx, num_recvd, NULL);
		}


		//tx
		struct rte_mbuf *tx[32];
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->outring, (void**)tx, BURST_SIZE, NULL);//dequeue the msg and send through the network card
		if(nb_tx > 0){
			rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);
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
