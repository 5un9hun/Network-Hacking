#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "pstruct.h"

void usage() {
	printf("syntax: airodump <interface>\n");
	printf("sample: airodump mon0\n");
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

void print_mac(u_int8_t mac[]) {
	for(int i = 0; i < 6; i++) {
		printf(" %02x ", mac[i]);	
		if(i != 5) printf(":");		
	}
}

bool check_bssid(u_int8_t past[], u_int8_t curr[]) {
	for(int i = 0; i < 6; i++) {
		if(past[i] != curr[i]) {
			if(past[i] == 0x0) continue;
			return 1;
		}
	}
	return 0;
}

void assign_bssid(u_int8_t dst[], u_int8_t src[]) {
	for(int i = 0; i < 6; i++) {
		dst[i] = src[i];
	}
}

void assign_essid(u_char* dst, u_char* src, int len) {
	memset(dst, 0, 30);
	for(int i = 0; i < len; i++) {
		dst[i] = src[i];
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
	
	int beacons = 0;
	int old_beacons = 0;
	u_int8_t past_bssid[6] = { 0, };
	u_int8_t curr_bssid[6] = { 0, };
	u_char past_essid[30] = { 0, };

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		
		struct ieee80211_radiotap_header* radioTap;
		struct beacon_frame_header* beaconFrame;
		struct fixed_parameters* fixed;
		struct tagged_parameters* tagged;
		
		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		radioTap = (ieee80211_radiotap_header*)(packet);
		int radio_len = radioTap->it_len;
		beaconFrame = (beacon_frame_header*)(packet + radio_len);
		
		if(beaconFrame->fcf.subtype == 0x8 && beaconFrame->fcf.type == 0x0 && beaconFrame->fcf.version == 0x0) {
		
			int beacon_len = sizeof(struct beacon_frame_header);
			fixed = (fixed_parameters*)(packet + radio_len + beacon_len);
			int fixed_len = sizeof(struct fixed_parameters) - 4; //struct padding
			tagged = (tagged_parameters*)(packet + radio_len + beacon_len + fixed_len);
			int tagged_len = sizeof(struct tagged_parameters);
			int essid_len = tagged->tag_length;
			
			u_char* essid = (u_char*)(packet + radio_len + beacon_len + fixed_len + tagged_len);
			essid[essid_len] = 0;
			
			assign_bssid(curr_bssid, beaconFrame->bss_id);
			/*
			printf("=======debug======\n");
			print_mac(curr_bssid);
			printf("\n");
			print_mac(past_bssid);
			printf("==================\n");*/
			if(check_bssid(past_bssid, curr_bssid)) {
				old_beacons = beacons;
				printf("\n[BSSID] ");
				print_mac(past_bssid);
				printf("\t[ESSID] %-30s", past_essid);
				printf("\t[Beacons] : %d\n", old_beacons);
				assign_bssid(past_bssid, beaconFrame->bss_id);
				assign_essid(past_essid, essid, essid_len);
				beacons = 1;
			}
			else {
				beacons++;
				assign_bssid(past_bssid, beaconFrame->bss_id);
			}		
		}
	}
	pcap_close(pcap);
}
