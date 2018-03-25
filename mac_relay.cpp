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
int main(int argc, char **argv){
    char errbuf[PCAP_ERRBUF_SIZE];
    cout<<"pcap_file_header "<<sizeof(pcap_file_header)<<endl;
    cout<<"pcap_pkthdr "<<sizeof(pcap_pkthdr)<<endl;
    pcap_t* descr;
    //const u_char *packet;
    char packet[2048];
    struct pcap_pkthdr* hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    struct udphdr *udpptr;
    u_char *ptr;
    descr = pcap_open_live("eth0", 65535, 1, -1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
    int res = 0;
    while(true){
    	res = pcap_next_ex(descr, &hdr, (const u_char**)packet);
    	printf("pakcet len is %d\n", hdr->caplen);
    	if(pcap_sendpacket(descr, (const u_char*)packet, hdr->caplen)!=0){
    	    		fprintf(stderr, "\n!!!!Error sending the packet:\n", pcap_geterr(descr));
    	    	}
    	//if(res<=0) continue;
        eptr = (struct ether_header *) packet;
    	struct ether_header new_eth_header;
    	printf("type is %.4x\n", ntohs(eptr->ether_type));
    	printf("13 14 is %.2x-%.2x\n", packet[12],packet[13]);
    	if(ntohs(eptr->ether_type)!=0x800) continue;
    	printf("original___%.2x-%.2x-%.2x-%.2x-%.2x-%.2x---%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", packet[0],packet[1],packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
    	for(int i=0;i<6;i++)
    		swap(packet[i],packet[i+6]);
    	printf("new________%.2x-%.2x-%.2x-%.2x-%.2x-%.2x---%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n", packet[0],packet[1],packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
    	if(pcap_sendpacket(descr, (const unsigned char*)packet, hdr->caplen)!=0){
    		fprintf(stderr, "\nError sending the packet:\n", pcap_geterr(descr));
    	}
    	//printf("^^^^^%d\n",res);
    }
    return 0;
}


