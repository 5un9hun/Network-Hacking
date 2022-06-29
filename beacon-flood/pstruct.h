#include <pcap.h>
#include <stdint.h>

#pragma pack (push, 1)

struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
};

/*=================beacon======================*/
struct frame_control_field {
		u_int8_t		version:2;
		u_int8_t		type:2;
		u_int8_t		subtype:4;
		u_int8_t		flags;
};

struct beacon_frame_header {
		struct frame_control_field fcf;
		u_int16_t		duration;
		u_int8_t		dst_addr[6];
		u_int8_t		src_addr[6];
		u_int8_t		bss_id[6];
		u_int16_t		fragment_number:4;
		u_int16_t		sequence_number:12;
};


/*parameter - https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/*/

struct fixed_parameters {
		u_int64_t		timestamp;
		u_int16_t		beacon_interval;
		u_int16_t		capability_information;
};


struct tagged_ssid {
		u_int8_t		tag_number;
		u_int8_t		tag_length;
};

/* ssid - dynamic */

struct tagged_supported {
		u_int8_t		tag_nubmer;
		u_int8_t		tag_length;
};

/* supprted rates - dynamic */
#pragma pack(pop)
