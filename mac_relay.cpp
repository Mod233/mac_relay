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
    const u_char *packet=(unsigned char*)malloc(2048);
    struct pcap_pkthdr* hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;
    struct udphdr *udpptr;
    u_char *ptr;
    //descr = pcap_open_offline(dir,errbuf);
    descr = pcap_open_live("any", 1576, 1, 2, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }
    int res = 0;
    while(true){
    	res = pcap_next_ex(descr, &hdr, &packet);
    	if(res<=0) continue;
    	cout<<"les is "<<res<<' '<<hdr->caplen<<endl;
    	cout<<packet<<endl;
    	printf("get packet.!\n");
    	eptr = (struct ether_header *) packet;
    	struct ether_header new_eth_header;

#if(0)
    	for(int i=0;i<ETH_ALEN;i++){
    		printf("i is %d\n",i);
    		printf("!!!%d\n",new_eth_header.ether_dhost[i]);
            printf("###%d\n",eptr[i]);
    		//new_eth_header.ether_dhost[i]=(u_int8_t)eptr->ether_shost[i];
    		//new_eth_header.ether_shost[i]=(u_int8_t)eptr->ether_dhost[i];

    	}
#endif

    	memcpy(new_eth_header.ether_shost, &(eptr->ether_dhost), 6) ;
    	memcpy(new_eth_header.ether_dhost, &(eptr->ether_shost), 6);

    	memcpy(&packet, &new_eth_header, 12);
    	printf("packet.!\n");
    	pcap_sendpacket(descr, (const unsigned char *)packet, hdr->caplen);
    	printf("^^^^^\n");
    }
    return 0;
}


