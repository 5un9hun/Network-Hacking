#include <pcap.h>
#include <stdint.h>

struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
};

struct deauthentication_header {
		u_int8_t		type;
		u_int8_t 		flag;
		u_int16_t		duration;
		u_int8_t		dst_mac[6];
		u_int8_t		src_mac[6];
		u_int8_t		bss_id[6];
		u_int16_t		number;
		
};

struct fixed_parameter {
		u_int16_t		reason_code;
};

struct deauthentication_packet {
		ieee80211_radiotap_header 	radiotap;
		deauthentication_header 	deauth_header;
		fixed_parameter				fixed;
};