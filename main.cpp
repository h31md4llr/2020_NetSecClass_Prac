#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <vector>

using namespace std;
vector<struct beacon_info> vinfo;

void usage()
{
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
}

#pragma pack(push, 1)
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct beacon_frame
{
	u_int8_t type;
	u_int8_t flags;
	u_int16_t duration;
	u_int8_t dmac[6];
	u_int8_t smac[6];
	u_int8_t bssid[6];
	u_int16_t ord;
	u_int8_t fparam[12];
	u_int8_t tagnum;
	u_int8_t len;
};

struct beacon_info
{
	u_int8_t bssid[6];
	int beacon = 0;
	char *name;
    int8_t pwr;
};
#pragma pack(pop)

int find_bssid(u_int8_t* bssid)
{
	for(int i = 0 ; i < vinfo.size() ; i++)
	{
		if(!memcmp(vinfo[i].bssid, bssid, 6))
		{
			vinfo[i].beacon++;
			return i;
		}
	}
	return -1;
}

int8_t get_pwr(const u_char* packet)
{
    u_int32_t present = *(u_int32_t*)(packet + 4);
    int idx = 12;

    if(!(present & 0x20))
        return 0;

    if(present & 0x1)
        idx += 8;
    if(present & 0x2)
        idx += 1;
    if(present & 0x4)
        idx += 1;
    if(present & 0x8)
        idx += 4;
    if(present & 0x10)
        idx += 1;
    if(present & 0x80000000)
        idx += 4;

    return *(int8_t*)(packet + idx);
}

int parse(const u_char* packet)
{
	struct beacon_frame* bframe;
    bframe = (struct beacon_frame*)malloc(sizeof(struct beacon_frame));

    u_int16_t hlen = *(packet + 2);
    memcpy(bframe, packet + hlen, sizeof(struct beacon_frame));

    if(bframe->type == 0x80)
    {
    	struct beacon_info tmp_info;
    	
    	for(int i = 0 ; i < 6 ; i++)
    		tmp_info.bssid[i] = bframe->bssid[i];

    	tmp_info.name = (char*)malloc((int)bframe->len);
    	memcpy(tmp_info.name, packet + hlen + sizeof(struct beacon_frame), bframe->len);

    	int res = find_bssid(tmp_info.bssid);
        int8_t tmpwr = get_pwr(packet);
    	if(res == -1)
    	{
    		tmp_info.beacon++;
            tmp_info.pwr = get_pwr(packet);
    		vinfo.push_back(tmp_info);
            free(bframe);
    		return 0;
    	}
        if(tmpwr != 0)
            vinfo[res].pwr = tmpwr;

    	free(tmp_info.name);
    }
    free(bframe);
}

void print_format()
{
	printf("BSSID\t\t\tPWR\tBeacon\tName\n");
	for(int i = 0 ; i < vinfo.size() ; i++)
	{
		printf("%02X:%02X:%02X:%02X:%02X:%02X\t", vinfo[i].bssid[0],vinfo[i].bssid[1],vinfo[i].bssid[2],vinfo[i].bssid[3],vinfo[i].bssid[4],vinfo[i].bssid[5]);	
        printf("%d\t", vinfo[i].pwr);
		printf("%d\t", vinfo[i].beacon);
		printf("%s\n", vinfo[i].name);
	}
}

int main(int argc, char* argv[]) {
    
    if (argc != 2) 
    {
        usage();
        return -1;
    }

    char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    int cnt = 0;
    while(1)
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

        parse(packet);
        system("clear");
        print_format();


    }

}