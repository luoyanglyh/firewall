#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/in_systm.h>
#include<netinet/tcp.h>
#include<netinet/if_ether.h>
#include<netinet/ether.h>
#include<net/ethernet.h>
#include<net/if.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include <time.h>
#include<pthread.h>
#include "uthash.h"


void capture_packet_eth0();
void capture_packet_eth1();
void packet_read(int,char *,pcap_t *);
char* next_packet(int *,pcap_t *);
void tcp_check(char *ptr, int len, struct ether_header *eptr,pcap_t *pd, char *orgptr);
int scan_packet(char *,char *,u_int16_t,u_int16_t);
void replace_destination_mac(struct ether_header *eptr, char* dest);
void replace_source_mac(struct ether_header *eptr);
void inject_packet(char *ptr, int len);
char* arping(char* ip);
void capture_packet_device();
void write_packet();
void offline_packet_read();
void identify_eth0_eth1(char* src);
char* checkinArpTable(char* ip);
void addinArpTable(char*ip, char*mac);

char* ETH0 = "eth0";
char* ETH1 = "eth1";
char* ETH0_MAC = "00:0c:29:7b:00:69";
char* ETH1_MAC = "00:0c:29:7b:00:73";
char* ETH0_IP = "30.10.1.128";
char* ETH1_IP = "20.10.1.128";

int is_incoming_to_eth1;
int is_offline;

struct arpvalue
{
	char* macptr;
	time_t timestamp;
};

struct filtering_rules
{
	char s_addr[16];
	char d_addr[16];
	u_int16_t s_port;
	u_int16_t d_port;
	int decision;
};

struct my_struct {
    char* ip;                    /* key */
    struct arpvalue val;
    UT_hash_handle hh;         /* makes this structure hashable */
};

typedef struct filtering_rules file_record;

FILE *fp;
pcap_t *pd;          /* packet capture struct pointer */
pcap_t *pdeth0;          /* packet capture struct pointer */
pcap_t *pdeth1;          /* packet capture struct pointer */
char* offline_file;
char* rules_file;
struct my_struct *arptable;

int main(int argc,char *argv[])
{
	arptable = NULL;    /* important! initialize to NULL */
    int err;
    pthread_t tid[2];

	if(argc <= 1){
		printf("Enter the arguments\n");
		return 1;
	}
	if(strcmp(argv[1],"0") == 0){
		if(argc <=3){
			printf("Enter 2 arguments after 0");
			return 1;
		}
		is_offline = 1;
		offline_file = argv[2];
		rules_file = argv[3];
		fp = fopen(rules_file,"r");
		capture_packet_device();
	}else{
		if(argc <=6){
			printf("Enter 7 arguments after 1");
			return 1;
		}
		is_offline = 0;
		ETH0 = argv[2];
		ETH0_IP = argv[3];
		ETH0_MAC = argv[4];
		ETH1 = argv[5];
		ETH1_IP = argv[6];
		ETH1_MAC = argv[7];
		rules_file = argv[8];
//		fp = fopen(rules_file,"r");

		err = pthread_create((tid + 0), NULL, capture_packet_eth1, NULL);
		if (err != 0)
			printf("\ncan't create thread :[%s]", strerror(err));
		else
			printf("\n Thread created successfully\n");

		err = pthread_create((tid + 1), NULL, capture_packet_eth0, NULL);
		if (err != 0)
			printf("\ncan't create thread :[%s]", strerror(err));
		else
			printf("\n Thread created successfully\n");

		pthread_join((tid[0]), NULL);
		pthread_join((tid[1]), NULL);

	}
//	fclose(fp);
	return(0);
}

void capture_packet_device(){
	char errbuf[PCAP_ERRBUF_SIZE];
	int datalink;        /* Type of datalink SLIP/PPP/Ethernet */
	char *ptr;                 /*Pointer to header */
	printf("Capture pcap file...........................");

	if((pd = pcap_open_offline(offline_file, errbuf)) == NULL)
	{                                                          /* Open device */
		printf("Error opening device: %s", errbuf);
	}

	if((datalink = pcap_datalink(pd)) < 0 )  /* returns type of datalink */
	{
		printf("Datalink error : %s", pcap_geterr(pd));
	}
	printf("Datalink = %d\n", datalink);

	offline_packet_read();
}

void capture_packet_eth0()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int datalink;        /* Type of datalink SLIP/PPP/Ethernet */
	char *ptr;                 /*Pointer to header */
	printf("Capture %s...........................", ETH0);
	printf("Handle for Device = %s",ETH0);
	if ((pdeth0 = pcap_open_live(ETH0, BUFSIZ, 1, 0, errbuf)) == NULL)
	{
		printf("Error opening device: %s", errbuf);
	}

	printf("Handle for Device = %s", ETH1);
	if ((pdeth1 = pcap_open_live(ETH1, BUFSIZ, 1, 0, errbuf)) == NULL)
	{
		printf("Error opening device: %s", errbuf);
	}

	if((datalink = pcap_datalink(pdeth0)) < 0 )  /* returns type of datalink */
	{
		printf("Datalink error : %s", pcap_geterr(pdeth0));
	}
	printf("Datalink = %d\n", datalink);

	packet_read(datalink,ptr,pdeth0);

}
void capture_packet_eth1()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int datalink;        /* Type of datalink SLIP/PPP/Ethernet */
	char *ptr;                 /*Pointer to header */
	printf("Capture %s...........................", ETH1);

	printf("Handle on Device = %s", ETH1);
	if ((pdeth1 = pcap_open_live(ETH1, BUFSIZ, 1, 0, errbuf)) == NULL)
	{
		printf("Error opening device: %s", errbuf);
	}
	printf("Handle on Device = %s", ETH0);

	if ((pdeth0 = pcap_open_live(ETH0, BUFSIZ, 1, 0, errbuf)) == NULL)
	{
		printf("Error opening device: %s", errbuf);
	}

	if((datalink = pcap_datalink(pdeth1)) < 0 )  /* returns type of datalink */
	{
		printf("Datalink error : %s", pcap_geterr(pdeth1));
	}
	printf("Datalink = %d\n", datalink);

	packet_read(datalink,ptr,pdeth1);

}
void packet_read(int datalink,char *ptr,pcap_t *pd)
{
	struct ether_header *eptr;
	int len;
	while(1)
	{
		ptr = next_packet(&len,pd); /* get next packet */
		switch(datalink)        /* check for link type */
		{
		case DLT_NULL:
			tcp_check(ptr + 4 , len - 4,eptr,pd, ptr); /* Loopback header = 4 bytes */
			break;

		case DLT_EN10MB:
			eptr = (struct ether_header *) ptr;    /* Ethernet header = 14 bytes */
			tcp_check(ptr + 14 , len - 14, eptr,pd, ptr);
			break;

		case DLT_SLIP:
			tcp_check(ptr + 24 , len - 24, eptr,pd, ptr);
			break;
			/* SLIP or PPP header = 24 bytes */
		case DLT_PPP:
			tcp_check(ptr + 24 , len - 24, eptr,pd, ptr);
			break;

		default :
			printf("Unsupported datalink");
			break;
		}

	}

}

void offline_packet_read(){
		write_packet();
		printf("see the capture.pcap\n");
}

char *next_packet(int *len,pcap_t *pd)
{
	char *ptr;
	struct pcap_pkthdr hdr;

	while((ptr = (char *) pcap_next(pd, &hdr)) == NULL); /* keep looping until packet ready */
	*len = hdr.caplen;                                   /* captured length */
	return(ptr);
}

void tcp_check(char *ptr, int len, struct ether_header *eptr,pcap_t *pd, char *orgptr)
{
	int hlen;
	struct ip *iphdr;
	struct tcphdr *tcph;
	char *src, *dest;
	char *srcmac, *dstmac;
	char *start;
	char *tempPtr;
	u_int16_t sport,dport;
	int size;
	struct ether_header *orgeptr;
	iphdr = (struct ip*) ptr;         /* Get IP header */
	orgeptr = (struct ether_header *) orgptr;    /* Ethernet header = 14 bytes */

	size = ntohs(iphdr->ip_len);
	start = (char *)malloc(size);
	memcpy(start,ptr,size);

	hlen = iphdr->ip_hl * 4;
	tempPtr = inet_ntoa(iphdr->ip_src);
	src = (char *)malloc(strlen(tempPtr) + 1);
	strncpy(src, tempPtr, strlen(tempPtr) + 1);

	tempPtr = inet_ntoa(iphdr->ip_dst);
	dest = (char *)malloc(strlen(tempPtr) + 1);
	strncpy(dest, tempPtr, strlen(tempPtr) + 1);

	identify_eth0_eth1(src);
	if(is_incoming_to_eth1 == -1){
		return;
	}

	tempPtr = ether_ntoa((struct ether_addr *)&orgeptr->ether_shost);
	srcmac = (char *)malloc(strlen(tempPtr) + 1);
	strncpy(srcmac, tempPtr, strlen(tempPtr) + 1);

	tempPtr = ether_ntoa((struct ether_addr *)&orgeptr->ether_dhost);
	dstmac = (char *)malloc(strlen(tempPtr) + 1);
	strncpy(dstmac, tempPtr, strlen(tempPtr) + 1);
	if(is_incoming_to_eth1 == 1){
		printf("On %s ", ETH1);
	}else{
		printf("On %s ", ETH0);
	}
	printf("Before srcip: %s srcmac: %s dstip: %s dstmac: %s\n",
					src,srcmac,dest,dstmac);

	//replace destination MAC
	replace_destination_mac(orgeptr, dest);

	//replace source MAC
	replace_source_mac(orgeptr);

	tempPtr = ether_ntoa((struct ether_addr *)&orgeptr->ether_shost);
	srcmac = (char *)malloc(strlen(tempPtr) + 1);
	strncpy(srcmac, tempPtr, strlen(tempPtr) + 1);

	tempPtr = ether_ntoa((struct ether_addr *)&orgeptr->ether_dhost);
	dstmac = (char *)malloc(strlen(tempPtr) + 1);
	strncpy(dstmac, tempPtr, strlen(tempPtr) + 1);

	if(is_incoming_to_eth1 == 1){
		printf("On %s ", ETH1);
	}else{
		printf("On %s ", ETH0);
	}
	printf("After srcip: %s srcmac: %s dstip: %s dstmac: %s\n",
				src,srcmac,dest,dstmac);

	switch(iphdr->ip_p){
	case IPPROTO_ICMP:
		sport = -1;
		dport = -1;
		break;
	case IPPROTO_TCP:
		ptr += hlen;
		tcph = (struct tcphdr *)ptr;  /* Get source and dest port */
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);
		ptr += sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		break;
	default:
		break;
	}

	if(scan_packet(src,dest,sport,dport) == 1)
	{
		printf("Packet allowed by firewall\n");
		inject_packet(orgptr, len+14);
	}else{
		printf("Packet blocked by firewall\n");
	}

	free(src);
	free(dest);
	free(srcmac);
	free(dstmac);
}


void identify_eth0_eth1(char* src){
	int i =0, dot_count = 0;

	while(dot_count < 2){
		if(src[i] == '.'){
			dot_count++;
		}
		if(src[i] != ETH0_IP[i]){
			break;
		}
		i++;
	}
	if(dot_count == 2){
		is_incoming_to_eth1 = 0;
		return;
	}
	dot_count = 0;
	while(dot_count < 2){
		if(src[i] == '.'){
			dot_count++;
		}
		if(src[i] != ETH1_IP[i]){
			break;
		}
		i++;
	}
	if(dot_count == 2){
		is_incoming_to_eth1 = 1;
		return;
	}
	is_incoming_to_eth1 = -1;


}
void inject_packet(char *ptr, int len){
	if(is_incoming_to_eth1 == 1){
		pcap_inject(pdeth0,ptr,len);
	}else if(is_incoming_to_eth1 == 0){
		pcap_inject(pdeth1,ptr,len);
	}
}

void replace_destination_mac(struct ether_header *eptr, char* dest){
	struct ether_addr *ether_d;
	int i;
	char *macptr = NULL;
	if((macptr = checkinArpTable(dest)) == NULL){
		macptr = arping(dest);
		if(macptr != NULL)
			addinArpTable(dest, macptr);
	}
	if(macptr != NULL){
		ether_d = ether_aton (macptr);
		for( i = 0; i < 6; i++){
			eptr->ether_dhost[i] = (u_int8_t)(ether_d->ether_addr_octet[i]);
		}
	}
}

void replace_source_mac(struct ether_header *eptr){
	struct ether_addr *ether_d;
	int i;
	if(is_incoming_to_eth1 == 0){
		ether_d = ether_aton (ETH1_MAC);
	}else if(is_incoming_to_eth1 == 1){
		ether_d = ether_aton (ETH0_MAC);
	}else{
		return;
	}
	for( i = 0; i < 6; i++)
		eptr->ether_shost[i] = (u_int8_t)(ether_d->ether_addr_octet[i]);
}

void dispatcher_handler(u_char *dumpfile,
		const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	int hlen;
	struct ip *iphdr;
	char *src, *dest;
	char *start;
	char *tempPtr;
	int size;

	iphdr = (struct ip*)(pkt_data+14);         /* Get IP header */
	size = ntohs(iphdr->ip_len);
	start = (char *)malloc(size);
	memcpy(start,pkt_data,size);

	hlen = iphdr->ip_hl * 4;
	tempPtr = inet_ntoa(iphdr->ip_src);
	src = (char *)malloc(strlen(tempPtr) + 1);
	strncpy(src, tempPtr, strlen(tempPtr) + 1);

	tempPtr = inet_ntoa(iphdr->ip_dst);
	dest = (char *)malloc(strlen(tempPtr) + 1);
	strncpy(dest, tempPtr, strlen(tempPtr) + 1);
	//save the packet on the dump file
	if(scan_packet(src,dest, -1,-1) == 1){
		pcap_dump(dumpfile,header,pkt_data);
	}

}

void write_packet(){
	//open the dump file
	pcap_t *pdo;
	pcap_dumper_t *pdumper;

	pdo = pcap_open_dead(1, 65535 /* snaplen */);
	/* Create the output file. */
	pdumper = pcap_dump_open(pdo, "capture.pcap");
	if(pdumper==NULL){
		fprintf(stderr,"\nError opening output file\n");
		return;
	}
	//start the capture
	pcap_loop(pd, -1, dispatcher_handler, (unsigned char *)pdumper);
}

void addinArpTable(char*ip, char*mac){
	struct my_struct *t, *s, *u, *tmp;
	struct timeval tv;
	char* addip;
	addip = (char *)malloc(strlen(ip) + 1);
	strncpy(addip, ip, strlen(ip) + 1);

	char* addmac;
	addmac = (char *)malloc(strlen(mac) + 1);
	strncpy(addmac, mac, strlen(mac) + 1);

	time_t current;
	HASH_FIND_STR(arptable, ip,t);
	if(t == NULL){
		s = malloc(sizeof(struct my_struct));
		s->ip= addip;
		s->val.macptr = (char *)malloc(strlen(addmac) + 1);
		strncpy(s->val.macptr, addmac, strlen(addmac) + 1);
		gettimeofday(&tv,NULL);
		current = &tv.tv_sec;
		s->val.timestamp = current;
		HASH_ADD_KEYPTR( hh, arptable, s->ip, strlen(s->ip), s );
		printf("Added ip %s in arp table\n", ip);
	}
	HASH_ITER(hh, arptable, u, tmp) {
			printf("After adding %s\n",u->ip);
			printf("After adding %s\n",u->val.macptr);

	}
	free(addip);
	free(addmac);
}

char* checkinArpTable(char* ip){
	struct my_struct *t, *s,*tmp;
	struct timeval tv;
	time_t current;
	time_t prev;
	char* checkip;
	checkip = (char *)malloc(strlen(ip) + 1);
	strncpy(checkip, ip, strlen(ip) + 1);
	HASH_ITER(hh, arptable, s, tmp) {
		printf("******%s\n",s->ip);
		printf("******%s\n",s->val.macptr);
	}
	HASH_FIND_STR(arptable, checkip,t);
	if(t != NULL){
		gettimeofday(&tv,NULL);
		current = &tv.tv_sec;
		prev = t->val.timestamp;
		if(difftime(current, prev) > 60){
			printf("Deleting %s as this is stale\n", checkip);
			HASH_DEL(arptable, t);  /* user: pointer to deletee */
			free(t);
			return NULL;
		}else{
			printf("Already present ip - %s. returning it\n", checkip);
			return t->val.macptr;
		}
	}
	printf("Not in arptable %s", checkip);
	free(checkip);
	return NULL;
}

char* arping(char* ip){
	char cmd[50] = "arping -c 1 -I ";
	if(is_incoming_to_eth1 == 1){
		strcat(cmd,ETH0);
		strcat(cmd," ");
	}else{
		strcat(cmd,ETH1);
		strcat(cmd," ");
	}
	strcat(cmd,ip);
	char buf[BUFSIZ];
	char mac[20];
	char* macptr = NULL;
	FILE *ptr;
	if ((ptr = popen(cmd, "r")) != NULL)
	while (fgets(buf, BUFSIZ, ptr) != NULL){
//	  (void) printf("%s", buf);
	  int i = 0, j = 0;
	  int is_capture = 0;
	  while(buf[i]){
		  if(buf[i] =='['){
			  is_capture = 1;
		  }
		  if(buf[i] == ']'){
			  mac[j] ='\0';
			  break;
		  }
		  if(is_capture == 1 && buf[i] !='['){
			  mac[j] = buf[i];
			  j++;
		  }
		  i++;
	  }
	}
	(void) pclose(ptr);
	if(mac[0] != '\0')
		macptr = mac;
	else
		printf("mac is null");
	return macptr;
}
//Callback function called by libpcap for every incoming packet


int scan_packet(char *src,char *dest,u_int16_t sport,u_int16_t dport)
{
//	file_record frecord;
//	rewind(fp);
//
//	while(!feof(fp))
//	{
//		fscanf(fp,"%s %s %d %d %d",frecord.s_addr,frecord.d_addr,&frecord.s_port,&frecord.d_port,&frecord.decision);
////		puts("Entered");
////		puts(frecord.s_addr);
//		if(strcmp(frecord.s_addr,src) == 0)
//		{
////			puts("Matched Src");
//			if(strcmp(frecord.d_addr,dest) == 0)
//			{
////				puts("Matched Dst");
//				if(frecord.s_port == sport)
//				{
////					puts("Matched Src port");
//
//					if(frecord.d_port == dport)
//					{
////						puts("Matched Dst port");
////						printf("Decision: %d\n",frecord.decision);
//						return(frecord.decision);
//					}
//				}
//			}
//		}
//
//	}
	return(1);

}

