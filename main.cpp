#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>

const char *blockmsg = "blocked!!!";

#pragma pack(push, 1)
typedef struct packet_hdr
{
	struct libnet_ethernet_hdr eth;
	struct libnet_ipv4_hdr ipv4;
	struct libnet_tcp_hdr tcp;
}packet_hdr;
#pragma pack(pop)

void usage()
{
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

int check_pattern(struct packet_hdr *packet, char* pattern)
{
	int data_len = packet->ipv4.ip_len - (packet->ipv4.ip_hl * 4) - (packet->tcp.th_off * 4);
	uint8_t *data = (uint8_t*)&(packet->tcp) + packet->tcp.th_off * 4;

	for(int i = 0 ; i < data_len - strlen(pattern) ; i++)
	{
		if(!memcmp(data + i, pattern, strlen(pattern)))
			return 1;
	}
	return 0;
}

u_short ip_checksum(struct libnet_ipv4_hdr* ip_hdr)
{
	u_char* raw = (u_char*)ip_hdr;
	int sum = 0;
	
	for(int i = 0 ; i < (ip_hdr->ip_hl * 4) ; i+=2)
	{
		sum += *(u_short*)(raw + i);
		printf("%04x ", *(u_short*)(raw+i));
	}
	printf("\nsum : %08x\n", sum);

	u_short checksum = sum >> 16;
	checksum += sum & 0xffff;

	printf("checksum : %04x\n", checksum);
	return checksum ^ 0xffff;
}

u_short tcp_checksum(struct libnet_ipv4_hdr* ip_hdr, struct libnet_tcp_hdr* tcp_hdr)
{
	u_char* ip_raw = (u_char*)ip_hdr;
	u_char* tcp_raw = (u_char*)tcp_hdr;
	int sum = 0;
	u_short tcp_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4);

	for(int i = 12; i < 20; i += 2)
		sum += *(u_short*)(ip_raw + i);

	sum += htons(6);
	sum += htons(tcp_len);

	for(int i = 0 ; i < tcp_len ; i += 2)
	{
		sum += *(u_short*)(tcp_raw + i);
	}

	u_short checksum = sum >> 16;
	checksum += sum & 0xffff;
	return checksum ^ 0xffff;
}

void send_rst(pcap_t *handle, struct packet_hdr *b_packet)
{
	int size = sizeof(struct libnet_ethernet_hdr) + (b_packet->ipv4.ip_hl * 4) + (b_packet->tcp.th_off * 4);
	int data_len = ntohs(b_packet->ipv4.ip_len) - (b_packet->ipv4.ip_hl * 4) - (b_packet->tcp.th_off * 4);
	printf("data_len : %d\n", data_len);

	uint8_t *new_packet = (uint8_t*)malloc(size);
	memcpy(new_packet, b_packet, size);
	struct packet_hdr *new_hdr = (struct packet_hdr*)new_packet;

	new_hdr->ipv4.ip_len = htons((b_packet->ipv4.ip_hl * 4) + (b_packet->tcp.th_off * 4));
	new_hdr->ipv4.ip_sum = 0;
	new_hdr->ipv4.ip_sum = ip_checksum(&(new_hdr->ipv4));

	new_hdr->tcp.th_seq = htonl(ntohl(b_packet->tcp.th_seq) + data_len);
	new_hdr->tcp.th_flags |= 0x14;
	new_hdr->tcp.th_sum = 0;
	new_hdr->tcp.th_sum = tcp_checksum(&(new_hdr->ipv4), &(new_hdr->tcp));

	int res = pcap_sendpacket(handle, (uint8_t*)new_hdr, size);

	if(res != 0)
		printf("[!] Failed to send RST packet!\n");

	free(new_packet);

}

void send_fin(pcap_t *handle, struct packet_hdr *b_packet)
{
	int size = sizeof(struct libnet_ethernet_hdr) + (b_packet->ipv4.ip_hl * 4) + (b_packet->tcp.th_off * 4) + strlen(blockmsg);
	int data_len = ntohs(b_packet->ipv4.ip_len) - (b_packet->ipv4.ip_hl * 4) - (b_packet->tcp.th_off * 4);

	uint8_t *new_packet = (uint8_t*)malloc(size);
	memcpy(new_packet, b_packet, size);
	struct packet_hdr *new_hdr = (struct packet_hdr*)new_packet;

	memcpy((uint8_t*)&(new_hdr->tcp) + new_hdr->tcp.th_off * 4, blockmsg, strlen(blockmsg));
	printf("strlen : %d\n", strlen(blockmsg));

	memcpy(new_hdr->eth.ether_dhost, b_packet->eth.ether_shost, 6);
	memcpy(new_hdr->eth.ether_shost, b_packet->eth.ether_dhost, 6);

	new_hdr->ipv4.ip_len = htons((b_packet->ipv4.ip_hl * 4) + (b_packet->tcp.th_off * 4) + strlen(blockmsg));
	printf("ntohs(ip_len): %d\n", ntohs(new_hdr->ipv4.ip_len));
	new_hdr->ipv4.ip_ttl = 128;
	new_hdr->ipv4.ip_src = b_packet->ipv4.ip_dst;
	new_hdr->ipv4.ip_dst = b_packet->ipv4.ip_src;
	new_hdr->ipv4.ip_sum = 0;
	new_hdr->ipv4.ip_sum = ip_checksum(&(new_hdr->ipv4));

	new_hdr->tcp.th_sport = b_packet->tcp.th_dport;
	new_hdr->tcp.th_dport = b_packet->tcp.th_sport;
	new_hdr->tcp.th_seq = b_packet->tcp.th_ack;
	new_hdr->tcp.th_ack = htonl(ntohl(b_packet->tcp.th_seq) + data_len);
	new_hdr->tcp.th_flags |= 0x11;
	new_hdr->tcp.th_sum = 0;
	new_hdr->tcp.th_sum = tcp_checksum(&(new_hdr->ipv4), &(new_hdr->tcp));

	int res = pcap_sendpacket(handle, (uint8_t*)new_hdr, size);

	if(res != 0)
		printf("[!] Failed to send RST packet!\n");

	free(new_packet);
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		usage();
		return -1;
	}

	char* dev = argv[1];
	char* pattern = argv[2];

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while(true)
    {
    	struct pcap_pkthdr* header;
    	const u_char* packet;
    	int res = pcap_next_ex(handle, &header, &packet);

    	if (res == 0) continue;
        if (res == -1 || res == -2) 
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct packet_hdr *hdr = (struct packet_hdr*)packet;

        if(ntohs(hdr->eth.ether_type) != ETHERTYPE_IP)
        {
            printf("[!]NOT IPV4\n");
            continue;
        }
        
        if(hdr->ipv4.ip_p != IPPROTO_TCP)
        {
            printf("[!]NOT TCP\n");
            continue;
        }

        if(check_pattern(hdr, pattern))
        {
        	send_rst(handle, hdr);
        	send_fin(handle, hdr);
        	printf("blocked!!!\n");
        }
    }
    pcap_close(handle);
}