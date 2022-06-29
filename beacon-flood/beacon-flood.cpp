#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <unistd.h>
#include <vector>
#include <iostream>
#include "pstruct.h"

u_int8_t ap[6] = {0x70, 0x5d, 0xcc, 0x8a, 0x92, 0x5a};
u_int8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
std::vector<std::string> ssid_list;

void usage() {
	printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
	printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

void set_mac(u_int8_t target[], u_int8_t value[]) {
	for(int i = 0; i < 6; i++) {
		target[i] = value[i];
	}
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	
	std::ifstream ifs;
	ifs.open(argv[2]);
	if(ifs.is_open()) {
		while(!ifs.eof()) {
			char buf[256];
			ifs.getline(buf, 256);
			ssid_list.push_back(std::string(buf));
		}
	}
	ifs.close();
	
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

	struct ieee80211_radiotap_header *radio = (ieee80211_radiotap_header*)malloc(sizeof(ieee80211_radiotap_header));
	struct beacon_frame_header *beacon = (beacon_frame_header*)malloc(sizeof(beacon_frame_header));
	struct fixed_parameters *fixed = (fixed_parameters*)malloc(sizeof(fixed_parameters));
	struct tagged_ssid *ssid = (tagged_ssid*)malloc(sizeof(tagged_ssid));
	//struct tagged_supported *supported = (tagged_supported*)malloc(sizeof(tagged_supported));
	
	std::vector<std::string>::iterator it = ssid_list.begin();

	while (true) {
		
		memset(radio, 0, sizeof(ieee80211_radiotap_header));
		radio->it_len = 8;
	
		memset(beacon, 0, sizeof(beacon_frame_header));
		beacon->fcf.subtype = 8;
		set_mac(beacon->dst_addr, broadcast);
		set_mac(beacon->src_addr, ap);
		set_mac(beacon->bss_id, ap);
				
		memset(fixed, 0, sizeof(fixed_parameters));
		//fixed->capability_information = 0xc11;
	
		memset(ssid, 0, sizeof(tagged_ssid));
		ssid->tag_length = (*it).size();
		char* ssid_name = (char*)malloc(sizeof(ssid->tag_length));
		ssid_name = const_cast<char*>((*it).c_str());
	
		//memset(supported, 0, sizeof(tagged_supported));

		int total_size = sizeof(ieee80211_radiotap_header) + sizeof(beacon_frame_header) + sizeof(fixed_parameters) + sizeof(tagged_ssid) + ssid->tag_length; //sizeof(tagged_supported);
		
		u_char *result = (u_char*)malloc(total_size);
		memcpy(result, radio, sizeof(ieee80211_radiotap_header));
		result += sizeof(ieee80211_radiotap_header);
		memcpy(result, beacon, sizeof(beacon_frame_header));
		result += sizeof(beacon_frame_header);
		memcpy(result, fixed, sizeof(fixed_parameters));
		result += sizeof(fixed_parameters);
		memcpy(result, ssid, sizeof(tagged_ssid));
		result += sizeof(tagged_ssid);
		memcpy(result, ssid_name, ssid->tag_length);
		result += ssid->tag_length;
		//memcpy(result, supported, sizeof(tagged_supported));
		//result += sizeof(tagged_supported);

		result -= total_size;
	
		int res = pcap_sendpacket(pcap, result, total_size);
		if (res != 0) {
			printf("pcap_sendpacket return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("send packet\n");
		
		usleep(10000);
		
    	if (++it == ssid_list.end())
	      it = ssid_list.begin();
	}
	free(radio);
	free(beacon);
	free(fixed);
	free(ssid);
	//free(supported);
	pcap_close(pcap);
}
