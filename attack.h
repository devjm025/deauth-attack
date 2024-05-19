#include <iostream>
#include <cstdio>
#include <pcap.h>
#include "mac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <arpa/inet.h>

// ** you can need flag revision

struct authpkt {
    // Radiotap Header
    u_int8_t radiotap_hdr[18];

    // authentication
    u_int8_t flag[2];
    u_int16_t duration;

    Mac receiver_mac;
    Mac transmitter_mac;
    Mac bssid;

    u_int16_t frag_seq;
    u_int8_t fixed_params[6] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
};

struct assopkt{
    // Radiotap Header
    u_int8_t radiotap_hdr[18];

    // association request
    u_int8_t flag[2];
    u_int16_t duration;

    Mac receiver_mac;
    Mac transmitter_mac;
    Mac bssid;

    u_int16_t frag_seq;
    u_int8_t fixed_params[4] = {0x31, 0x04, 0x05, 0x00};
};



struct deauthpkt {
    // Radiotap Header
    u_int8_t radiotap_hdr[12] = {0x00};

    u_int8_t flag[2];
    u_int16_t duration;

    Mac receiver_mac;
    Mac transmitter_mac;
    Mac bssid;

    u_int16_t frag_seq;
    u_int16_t fixed_params;
};

void authentication(pcap_t* handle, Mac r_mac, Mac t_mac);
void deauth(pcap_t* handle, Mac r_mac, Mac t_mac, Mac bssid);
