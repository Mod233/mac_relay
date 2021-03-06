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
int main(int argc, char **argv) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr* hdr; /* pcap.h */
	struct ether_header *eptr; /* net/ethernet.h */
	struct iphdr *ipptr;
	struct tcphdr *tcpptr;
	struct udphdr *udpptr;
	u_char *ptr;
	descr = pcap_open_live("enp0s31f6", 65535, 0, 1, errbuf);   //no promisc
	if (descr == NULL) {
		printf("pcap_open_live(): %s\n", errbuf);
		exit(1);
	}
	int res = 0;
	while (true) {
		res = pcap_next_ex(descr, &hdr, &packet);
		if(hdr->caplen<1) continue;
//		printf("get packet\n");
		int caplen = hdr->caplen;
		eptr = (struct ether_header *) packet;
		if (ntohs(eptr->ether_type) != 0x800)
			continue;
		u_char tmp[6];
		memcpy(tmp, eptr->ether_dhost, 6);
		memcpy(eptr->ether_dhost, eptr->ether_shost, 6);
		memcpy(eptr->ether_shost, tmp, 6);
//		printf("sds\n"); // why we must add it???
		ipptr = (struct iphdr*) (packet + sizeof(ether_header));
		struct in_addr srcip, dstip;
		srcip.s_addr = in_addr_t(ipptr->saddr);
		dstip.s_addr = in_addr_t(ipptr->daddr);
		std::string sip = inet_ntoa(srcip);
		std::string dip = inet_ntoa(dstip);
//		cout << "sip is " << sip << ' ' << "dip is " << dip << endl;
		if (ipptr->protocol == 17) {
			udpptr = (struct udphdr *) (packet + sizeof(ether_header)
					+ (ipptr->ihl) * 4);
//			printf("sport is %u dport is %u\n", ntohs(udpptr->source),
//					ntohs(udpptr->dest));
			char udpbuf[1024];
			char pattern1[13]={"hello world"};
			char pattern2[13] = { "world hello" };
			int udplen = ntohs(udpptr->len) - 8;
			memcpy(udpbuf,
					(void*) (packet + sizeof(ether_header) + (ipptr->ihl) * 4
							+ 8), udplen);
//			printf("udpbuf is %s\n", udpbuf);
//			printf("udp cpy succed\n");
			int pos = 0;
			while (pos < caplen - 6) {
				if (packet[pos] == 'h' && packet[pos + 1] == 'e'
						&& packet[pos + 2] == 'l' && packet[pos + 3] == 'l'
						&& packet[pos + 4] == 'o') {
					memcpy((void*) (packet + pos), pattern2, strlen(pattern2));
				}
				pos++;
			}
		} else if (ipptr->protocol == 6) {
			tcpptr = (struct tcphdr *) (packet + sizeof(ether_header)
					+ (ipptr->ihl) * 4);
//			printf("sport is %u dport is %u\n", ntohs(tcpptr->source),
//					ntohs(tcpptr->dest));
			char pattern2[13] = { "world hello" };
			int tcplen = ntohs(ipptr->tot_len) - (ipptr->ihl) * 4
					- (tcpptr->th_off) * 4;
			char tcpbuf[1024];
			memcpy(tcpbuf,
					(packet + sizeof(ether_header) + (ipptr->ihl) * 4
							+ (tcpptr->th_off) * 4), tcplen);
//			printf("tcp buf is %s\n", tcpbuf);
//			printf("tcp cpy succed\n");
			int pos = 0;
			while ((int)(strlen(tcpbuf) - 6 )> pos) {
				if (tcpbuf[pos] == 'h' && tcpbuf[pos + 1] == 'e'
						&& tcpbuf[pos + 2] == 'l' && tcpbuf[pos + 3] == 'l')
					memcpy(
							(void*) (packet + pos + sizeof(ether_header)
									+ (ipptr->ihl) * 4 + (tcpptr->th_off) * 4),
							pattern2, strlen(pattern2));
				pos++;
//				printf("pos is %d\n", pos);
//				printf("buf len is %d\n", strlen(tcpbuf)-6);
			}
		}
		if (pcap_sendpacket(descr, (const unsigned char*) packet, hdr->caplen)
				!= 0) {
			fprintf(stderr, "\nError sending the packet:\n",
					pcap_geterr(descr));
		}

	}
	return 0;
}

