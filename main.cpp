#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

//temp
#include <iostream>
//

#define MAC_LEN 6
#define GW_IP_MAX_LEN 16



#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)


void usage() {
    printf("syntax: send-arp-test <interface> sender_IP victim_IP\n");
    printf("sample: send-arp-test wlan0 X.X.X.X X.X.X.X\n");
}


const char* get_mac(char* eth_interface){
    char* addr = (char*)malloc(MAC_LEN * 3);
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, eth_interface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        int i;
        int size;
        size = sprintf(addr, "%02x:", (unsigned char)s.ifr_addr.sa_data[0]);
        for (i = 1; i < MAC_LEN; ++i){
            if (i != MAC_LEN - 1)
                size += sprintf(addr+size, "%02x:", (unsigned char)s.ifr_addr.sa_data[i]);
            else
                size += sprintf(addr+size, "%02x\0", (unsigned char)s.ifr_addr.sa_data[i]);
        }
        return addr;
    }
}


void get_gw_ip(char* gw_ip){
    FILE *fp = popen("route -n | grep 'UG' | awk '{print $2}'", "r");
    fgets(gw_ip, GW_IP_MAX_LEN, fp);
    pclose(fp);
    printf("%s", gw_ip);
}


void get_gw_mac(pcap_t* pcap, char* mac){
    struct pcap_pkthdr* header;
    const u_char* p;

    while(true){
        int res = pcap_next_ex(pcap, &header, &p);
        if (res != 1) continue;

        struct EthHdr* eth_hdr = (EthHdr*)p;
        struct ArpHdr* arp_hdr = (ArpHdr*)(p+sizeof(struct EthHdr));

//        printf("type: %x, arp: %x\n", eth_hdr->type(), eth_hdr->Arp);
        if(eth_hdr->type() != eth_hdr->Arp) continue;


        const uint8_t* mac_tmp = arp_hdr->smac().getMac();

        int size = sprintf(mac, "%02x:", mac_tmp[0]);
        for(int i=1; i < MAC_LEN; i++){
            if(i != MAC_LEN-1){
                size += sprintf(mac+size, "%02x:", mac_tmp[i]);
            }
            else{
                sprintf(mac+size, "%02x", mac_tmp[i]);
            }
        }
        break;
    }
}


void arp_packet(EthArpPacket p, const char* s_mac, const char* v_dmac, const char* v_tmac, uint16_t op, const char* s_ip, const char* v_ip){
    p.eth_.smac_ = Mac(s_mac);
    p.eth_.dmac_ = Mac(v_dmac);
    p.eth_.type_ = htons(EthHdr::Arp);

    p.arp_.hrd_ = htons(ArpHdr::ETHER);
    p.arp_.pro_ = htons(EthHdr::Ip4);
    p.arp_.hln_ = Mac::SIZE;
    p.arp_.pln_ = Ip::SIZE;
    p.arp_.op_ = htons(op);
    p.arp_.smac_ = Mac(s_mac);
    p.arp_.sip_ = htonl(Ip(s_ip));
    p.arp_.tmac_ = Mac(v_tmac);
    p.arp_.tip_ = htonl(Ip(v_ip));
}


int main(int argc, char* argv[]) {
    // printf("argc: %d\n", argc);
    if (argc < 2) { // ----------------------------- the part which need to modify --------------------- //
        usage();
        return -1;
    }

    char* dev = argv[1];
    char* sender_ip = argv[2];
    char* victim_ip = argv[3];
    // printf("sender: %s, victim: %s\n", sender_ip, victim_ip);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);  // need to modify
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    const char* sender_mac = get_mac(dev);
    const char gw_dmac[18] = "ff:ff:ff:ff:ff:ff";
    const char gw_tmac[18] = "00:00:00:00:00:00";
    char gw_ip[GW_IP_MAX_LEN];
    get_gw_ip(gw_ip);

    EthArpPacket packet;

    arp_packet(packet, sender_mac, gw_dmac, gw_tmac, ArpHdr::Request, sender_ip, gw_ip);
    int res_request = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res_request != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_request, pcap_geterr(handle));
    }

    char gw_mac[MAC_LEN*3];
    get_gw_mac(handle, gw_mac);
    printf("%s\n", gw_mac);


//    arp_packet(packet, sender_mac, gw_dmac, gw_tmac, ArpHdr::Request, gw_ip, victim_ip); ///confused


    pcap_close(handle);

    free((void*)sender_mac);
}
