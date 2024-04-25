#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

void usage()
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

void print_mac_info(libnet_ethernet_hdr *eth_hdr)
{
    printf("[*] source_mac = %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    printf("[*] destination_mac = %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
}

void print_ip_info(libnet_ipv4_hdr *ip_hdr)
{
	uint8_t *src = (uint8_t *)&ip_hdr->ip_src;
	uint8_t *dst = (uint8_t *)&ip_hdr->ip_dst;
	printf("[*] source_ip = %d.%d.%d.%d\n", src[0], src[1], src[2], src[3]);
	printf("[*] destination_ip = %d.%d.%d.%d\n", dst[0], dst[1], dst[2], dst[3]);

}

void print_port_info(libnet_tcp_hdr *tcp_hdr)
{
	uint8_t *src = (uint8_t *)&tcp_hdr->th_sport;
	uint8_t *dst = (uint8_t *)&tcp_hdr->th_dport;
	printf("[*] source_port = %d\n", (src[0] << 8) + src[1]);
	printf("[*] destination_port = %d\n", (dst[0] << 8) + dst[1]);
}

void print_data16(uint8_t *p, unsigned int len)
{
	printf("[*] data = ");
	for(int i = 0 ; i < (len % 16) + 1 ; i++)
		printf("%02x ", p[i]);
	printf("\n");
}

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) 
	{
    	fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    	return -1;
	}

	while(true)
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("\n[*] %u bytes captured\n", header->caplen);

		// get ethernet_header from packet
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*) packet;
		if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
		{
			printf("[!] ether_type != ETHERTYPE_IP\n");
			continue;
		}


		// get ip_header from packet
		packet += sizeof(struct libnet_ethernet_hdr);
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*) packet;
		if(ip_hdr->ip_p != IPPROTO_TCP)
		{
			printf("[!] ip_p != IPPROTO_TCP\n");
			continue;
		}

		// print mac_address information

		print_mac_info(eth_hdr);

		// print ip_address information
		print_ip_info(ip_hdr);

		// get tcp_header from packet
		packet += sizeof(struct libnet_ipv4_hdr);
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*) packet;

		// print port information
		print_port_info(tcp_hdr);


		// print data
		packet += (tcp_hdr->th_off * sizeof(uint32_t));
		unsigned int data_len = header->caplen - sizeof(struct libnet_ethernet_hdr) - sizeof(struct libnet_ipv4_hdr) - (tcp_hdr->th_off * sizeof(uint32_t));
		print_data16((uint8_t *)packet, data_len);
	}

	pcap_close(handle);
	return 0;
}