#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<cstdio>
#include<iostream>
#include<cstring>
#include<pcap.h>
using namespace std;

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header);

void usage()
{
    printf("syntax : pcap-test <interface>\n");
    printf("sample : pcap-test wlan0\n");
}

int main(int argc,char * argv[]){
    if(argc!=2){
        usage();
        return -1;
    }

    char * dev= argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle =pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    
    if(handle==nullptr){
        fprintf(stderr, "pcap_open_live(%s) return nullptr - $s\n",dev,errbuf);
    }
     
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res ==0) continue;
        if (res==-1 | res ==-2){ // 에러발생
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }
        dump_pkt(packet,header);
    }
    pcap_close(handle);
}

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header){
    struct ether_header * eth_hdr=(struct ether_header *)pkt_data;

    u_int16_t eth_type=ntohs(eth_hdr->ether_type);

    //if type is not IP, return function
    if(eth_type!=ETHERTYPE_ARP) return;

    struct ether_arp* arp_hdr=(struct ether_arp*)(pkt_data + sizeof(ether_header));

    printf("\nPacket Info=======================\n");

    //print pkt length
    printf("%u bytes captured\n", header->caplen);

    //print mac addr
    u_int8_t* dst_mac=eth_hdr ->ether_dhost;
    u_int8_t* src_mac=eth_hdr->ether_shost;

    printf("Dst MAC : %0x:%0x:%0x:%0x:%0x:%0x\n",
        dst_mac[0], dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
    printf("Src MAC : %0x:%0x:%0x:%0x:%0x:%0x\n",
        src_mac[0], dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);

    //print arp addr
    u_char* s_ip = arp_hdr->arp_spa;
    u_char* t_ip = arp_hdr->arp_tpa;

    printf("Sen IP : %d.%d.%d.%d\n", s_ip[0], s_ip[1], s_ip[2], s_ip[3]);
    printf("Tar IP : %d.%d.%d.%d\n", t_ip[0], t_ip[1], t_ip[2], t_ip[3]);
}
