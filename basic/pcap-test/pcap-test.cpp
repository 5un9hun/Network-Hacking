#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "pstruct.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		
		struct ethernet_header* eth;
		struct ipv4_header* ip;
		struct tcp_header* tcp;
		u_char* data;
		
		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		

		eth = (ethernet_header*)(packet);
		ip = (ipv4_header*)(packet + ETHER_LEN);
		tcp = (tcp_header*)(packet + ETHER_LEN + IPV4_LEN);
		data = (u_char*)(packet + ETHER_LEN + IPV4_LEN + TCP_LEN + TCP_OPTION);
		
		if(eth->ether_type == 0x0008 && ip->ip_p == 0x0006) { //ip == IPv4 && protocol == tcp
			printf("=====================================PACKET======================================\n|\t\t\t\t\t\t\t\t\t\t|\n");
			printf("|\t\t=============Ethernet Header=============\t\t\t|\n");
			printf("|\t\tSource mac : [");
			for(int i = 0; i < ETHER_ADDR_LEN; i++) {
				printf(" %02x ", eth->ether_shost[i]);			
				if(i != 5) printf(":");
			}
			printf("]\t\t\t|\n");
			printf("|\t\tDestination mac : [");
			for(int i = 0; i < ETHER_ADDR_LEN; i++) {
				printf(" %02x ", eth->ether_dhost[i]);	
				if(i != 5) printf(":");		
			}
			printf("]\t\t|\n|\t\t\t\t\t\t\t\t\t\t|\n");
			
			printf("|\t\t=============IP Header=============\t\t\t\t|\n");
			printf("|\t\tSource ip : [");
			printf(" %d.%d.%d.%d ", 
							(ip->ip_src.s_addr & 0x000000ff),
							(ip->ip_src.s_addr & 0x0000ff00) >> 8,
							(ip->ip_src.s_addr & 0x00ff0000) >> 16,
							(ip->ip_src.s_addr & 0xff000000) >> 24);		
			printf("]\t\t\t\t\t|\n");
			printf("|\t\tDestination ip : [");
			printf(" %d.%d.%d.%d ", 
							(ip->ip_dst.s_addr & 0x000000ff),
							(ip->ip_dst.s_addr & 0x0000ff00) >> 8,
							(ip->ip_dst.s_addr & 0x00ff0000) >> 16,
							(ip->ip_dst.s_addr & 0xff000000) >> 24);			
			printf("]\t\t\t\t|\n|\t\t\t\t\t\t\t\t\t\t|\n");
			
			printf("|\t\t=============TCP Header=============\t\t\t\t|\n");
			printf("|\t\tSource port : [");
			printf(" %d ", tcp->th_sport);			
			printf("]\t\t\t\t\t\t|\n");
			printf("|\t\tDestination port : [");
			printf(" %d ", tcp->th_dport);			
			printf("]\t\t\t\t\t|\n|\t\t\t\t\t\t\t\t\t\t|\n");
			
			printf("|\t\t=============Data(8bytes)=============\t\t\t\t|\n");
			printf("|\t\tData : [");

			int count = 0;
			for(int i = 0; i < 8; i++) {
				if(*data == 0x0d && *(data+1) == 0x0a) { //\r\n
					*data == 0;
					break;
				}
				if(i == 8) break;
				printf(" %c ", *data);
				data++;
			}
			printf("]\t\t\t\t\t|\n|\t\t\t\t\t\t\t\t\t\t|\n");
			printf("=================================================================================\n\n");
			memset(data, 0, 8);
		}
		else {
			continue;
		}
	}

	pcap_close(pcap);
}
