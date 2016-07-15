#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <netinet/if_ether.h>

void callback_packet(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *pkt_data){

        struct ethhdr *ether;
        struct ip *ip;
        struct iphdr *iph;
        struct tcphdr *tcp;

        unsigned short ether_type;
        struct ether_header *ep;
        ep = (struct ether_header *)pkt_data;

        ether = (struct ethhdr *)pkt_data;
        ip = (struct ip *)(pkt_data + sizeof(struct ether_header));
        iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
        tcp = (struct tcphdr*)(pkt_data + (ip->ip_hl) * 4 + sizeof(struct ethhdr));
        if(ntohs(ep->ether_type) == ETHERTYPE_IP){
        printf("Ethernet Src : %x %x %x %x %x %x \n",ether->h_source[0],ether->h_source[1],ether->h_source[2],ether->h_source[3],ether->h_source[4],ether->h_source[5]);
        printf("Ethernet dst : %x %x %x %x %x %x \n",ether->h_dest[0],ether->h_dest[1],ether->h_dest[2],ether->h_dest[3],ether->h_dest[4],ether->h_dest[5]);
        printf("IP Src : %s \n",inet_ntoa(*(struct in_addr *)&iph->saddr));
        printf("IP dst : %s \n",inet_ntoa(*(struct in_addr *)&iph->daddr));
                if (ip->ip_p == IPPROTO_TCP){
                printf("TCP src port :%d \n ",ntohs(tcp->source));
                printf("TCP dst port :%d \n ",ntohs(tcp->dest));
                }
        }
}

int main(int argc,char *argv[])
{
    char* dev;
    char errbuf[2048];
    pcap_t *handle;

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        printf("error\n");
    }
    handle = pcap_open_live(dev,BUFSIZ,0,1000, errbuf);
    if(handle == NULL){
        printf("error\n");
    }
    pcap_loop(handle, 0, callback_packet, NULL);
}
