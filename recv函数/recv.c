#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <arpa/inet.h>

#define NUM_MBUFS (4096-1)

int gDpdkPortId=0;

static const struct rte_eth_conf port_conf_default={
	.rxmode={.max_rx_pkt_len=RTE_ETHER_MAX_LEN}
};

static void ng_init_port(struct rte_mempool *mbuf_pool){
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
	if(rte_eth_rx_queue_setup(gDpdkPortId,0, 128, rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool)){
		rte_exit(EXIT_FAILURE,"Could not setup RX queue\n");
	}
	//set tx queue
	if(rte_eth_tx_queue_setup(gDpdkPortId,0, 128, rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool)){
		rte_exit(EXIT_FAILURE,"Could not setup RX queue\n");
	}

	if(rte_eth_dev_start(gDpdkPortId)<0){
		rte_exit(EXIT_FAILURE,"Could not start\n");
	}
	rte_eth_promiscuous_enable(gDpdkPortId);

};

//create udp package
static void create_eth_ip_udp(uint8_t *msg,size_t total_len, uint8_t *dst_mac, uint32_t src_ip, uint32_t dst_ip, uint16 src_port, uint16 dst_port){
	
	//ether hdr
	struct rte_ether_addr src_mac;
	struct rte_ether_hdr *eth=(struct rte_ether_hdr *)msg;
	rte_mencpy(eth->d_addr.addr_bytes. dst_mac,RTE_ETHER_ADDR_LEN);
	rte_eth_macaddr_get(gDpdkPortId, &src_mac);
	rte_mencpy(eth->s_addr.addr_bytes. src_mac,RTE_ETHER_ADDR_LEN);
	eth->ether_type=htons(RTE_ETHER_TYPE_IPV4);

	//ip hdr
	struct rte_ipv4_hdr *ip=(struct rte_ipv4_hdr *)(eth+1);
	ip->version_ihl= 0x45;
	ip->type_of_service= 0;
	ip->total_length= htons(total_len-sizeof(struct rte_ether_hdr));
	

}


int main(int argc, char*argv[]){
	if(rte_eal_init(argc,argv)<0){
		rte_exit(EXIT_FAILURE,"Error with EAL init\n");
	}
	
	struct rte_mempool *mbuf_pool=rte_pktmbuf_pool_create("mbuf pool",NUM_MBUFS,0,0,RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if(mbuf_pool==NULL){
		rte_exit(EXIT_FAILURE,"Cloud not create mbuf\n");
	}
	ng_init_port(mbuf_pool);
	printf("Start receivimg:");
	while(1){
	
		struct rte_mbuf *mbufs[32];
		unsigned num_recvd=rte_eth_rx_burst(gDpdkPortId, 0, mbufs, 32);
		if(num_recvd>32){	
			rte_exit(EXIT_FAILURE,"Cloud not create mbuf\n");
		}
		rte_eth_tx_burst();

		unsigned i=0;
		for(i=0;i<num_recvd;i++){
			struct rte_ether_hdr *ehdr=rte_pktmbuf_mtod(mbufs[i],struct rte_ether_hdr*);
			if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
				rte_pktmbuf_free(mbufs[i]);
				continue;//if not ipv4,then skip
			}
			struct rte_ipv4_hdr *iphdr=rte_pktmbuf_mtod_offset(mbufs[i],struct rte_ipv4_hdr *,sizeof(struct rte_ether_hdr));
			if(iphdr->next_proto_id==IPPROTO_UDP){
				struct rte_udp_hdr *udphdr=(struct rte_udp_hdr *)((unsigned char*)iphdr+sizeof(struct rte_ipv4_hdr));
				
				if(ntohs(udphdr->src_port)==8080){
					uint16_t length=ntohs(udphdr->dgram_len);
					*((char*)udphdr+length)='\0';
					//print
					struct in_addr addr;
					addr.s_addr=iphdr->src_addr;
					printf("src: %s:%d, ",inet_ntoa(addr),ntohs(udphdr->src_port));
					addr.s_addr=iphdr->dst_addr;
					printf("dst: %s:%d, length:%d --> %s\n ",inet_ntoa(addr),ntohs(udphdr->src_port),length,(char *)(udphdr+1));
				}				

			rte_pktmbuf_free(mbufs[i]);
			}
		}
	

	}
	




}
