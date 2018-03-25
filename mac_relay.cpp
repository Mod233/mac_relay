//============================================================================
// Name        : mac_relay.cpp
// Author      : cs
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <vector>
#include <netinet/udp.h>
using namespace std;
char *dir= "/mnt/myusbmount/Trojan_Monitor/beijing/dns/speed/speed_211.166.0.166-180.153.116.241:39483.pcap";
int main(int argc, char **argv){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    //char packet[2048];
    struct pcap_pkthdr* hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    struct udphdr *udpptr;
    u_char *ptr;
    descr = pcap_open_live("enp0s31f6", 65535, 0, 1000, errbuf);   //no promisc
//    descr = pcap_open_offline(dir,errbuf);
//    printf("####\n");
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
    int res = 0;
    while(true){
    	res = pcap_next_ex(descr, &hdr, &packet);
//    	printf("original___%.2x-%.2x-%.2x-%.2x-%.2x-%.2x---%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", packet[0],packet[1],packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
    	printf("pakcet len is %d\n", hdr->caplen);
        eptr = (struct ether_header *) packet;
    	struct ether_header new_eth_header;
//    	printf("type is %.4x\n", ntohs(eptr->ether_type));
//    	printf("13 14 is %.2x-%.2x\n", packet[12],packet[13]);
    	printf("###\n");
    	//if(ntohs(eptr->ether_type)!=0x800) continue;
    	if(packet[12]!=0x08 || packet[13]!=0x00) continue;

    	printf("@@@@\n");
    	printf("original___%.2x-%.2x-%.2x-%.2x-%.2x-%.2x---%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", packet[0],packet[1],packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
    	u_char tmp[6];
    	memcpy(tmp,eptr->ether_dhost,6);
    	memcpy(eptr->ether_dhost,eptr->ether_shost,6);
    	memcpy(eptr->ether_shost,tmp,6);

    	printf("new________%.2x-%.2x-%.2x-%.2x-%.2x-%.2x---%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", packet[0],packet[1],packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
    	if(pcap_sendpacket(descr, (const unsigned char*)packet, hdr->caplen)!=0){
    		fprintf(stderr, "\nError sending the packet:\n", pcap_geterr(descr));
    	}

    }
    return 0;
}


