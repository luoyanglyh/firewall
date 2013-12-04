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
void replace_destination_mac(struct ether_header *eptr, char* dest, int is_incoming_to_eth1);
void replace_source_mac(struct ether_header *eptr, int is_incoming_to_eth1);
void inject_packet(char *ptr, int len, int is_incoming_to_eth1);
char* arping(char* ip, int is_incoming_to_eth1);
void capture_packet_device();
void write_packet();
void offline_packet_read();
int identify_eth0_eth1(char* src);
char* checkinArpTable(char* ip);
void addinArpTable(char*ip, char*mac);

char* ETH0 = "eth0";
char* ETH1 = "eth1";
char* ETH0_MAC = "00:0c:29:7b:00:69";
char* ETH1_MAC = "00:0c:29:7b:00:73";
char* ETH0_IP = "30.10.1.128";
char* ETH1_IP = "20.10.1.128";
typedef struct filtering_rules file_record;

FILE *fp;
pcap_t *pd;          /* packet capture struct pointer */
pcap_t *pdeth0;          /* packet capture struct pointer */
pcap_t *pdeth1;          /* packet capture struct pointer */
char* offline_file;
char* rules_file;
struct my_struct *arptable;
pthread_rwlock_t lock;

struct arpvalue
{
	char mac[18];
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
    char ip[16];                    /* key */
    struct arpvalue val;
    UT_hash_handle hh;         /* makes this structure hashable */
};

int main(int argc,char *argv[])
{
	arptable = NULL;    /* important! initialize to NULL */
    int err;
    pthread_t tid[2];
    if (pthread_rwlock_init(&lock,NULL) != 0) printf("can't create rwlock");

	if(argc <= 1){
		printf("Enter the arguments\n");
		return 1;
	}
	if(strcmp(argv[1],"0") == 0){
		if(argc <=3){
			printf("Enter 2 arguments after 0");
			return 1;
		}
		offline_file = argv[2];
		rules_file = argv[3];
		fp = fopen(rules_file,"r");
		capture_packet_device();
	}else{
		if(argc <=6){
			printf("Enter 7 arguments after 1");
			return 1;
		}
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
	struct icmphdr *icmph;
	struct udphdr *udph;
	char  src[16], dest[16];
	char srcmac[18], dstmac[18];
	u_int16_t sport,dport;
    unsigned short id, seq;
	struct ether_header *orgeptr;
	iphdr = (struct ip*) ptr;         /* Get IP header */
	orgeptr = (struct ether_header *) orgptr;    /* Ethernet header = 14 bytes */
	hlen = iphdr->ip_hl * 4;
	strncpy(src,inet_ntoa(iphdr->ip_src), 16);

	strncpy(dest, inet_ntoa(iphdr->ip_dst),16);

	int is_incoming_to_eth1 = identify_eth0_eth1(src);
	if(is_incoming_to_eth1 == -1){
		return;
	}

	strncpy(srcmac, ether_ntoa((struct ether_addr *)&orgeptr->ether_shost),18);
	strncpy(dstmac, ether_ntoa((struct ether_addr *)&orgeptr->ether_dhost), 18);
	if(is_incoming_to_eth1 == 1){
		printf("On %s ", ETH1);
	}else{
		printf("On %s ", ETH0);
	}
	printf("Before srcip: %s srcmac: %s dstip: %s dstmac: %s\n",
					src,srcmac,dest,dstmac );

	//replace destination MAC
	replace_destination_mac(orgeptr, dest,is_incoming_to_eth1);

	//replace source MAC
	replace_source_mac(orgeptr,is_incoming_to_eth1);

	strncpy(srcmac, ether_ntoa((struct ether_addr *)&orgeptr->ether_shost), 18);

	strncpy(dstmac, ether_ntoa((struct ether_addr *)&orgeptr->ether_dhost), 18);

	if(is_incoming_to_eth1 == 1){
		printf("On %s ", ETH1);
	}else{
		printf("On %s ", ETH0);
	}
	printf("After srcip: %s srcmac: %s dstip: %s dstmac: %s\n",
				src,srcmac,dest,dstmac);
	switch(iphdr->ip_p){
	case IPPROTO_ICMP:
		icmph = (struct icmphdr *)ptr;
		sport = -1;
		dport = -1;
		memcpy(&id, (u_char*)icmph+4, 2);
		memcpy(&seq, (u_char*)icmph+6, 2);
		printf("----------------ID:%d Seq:%d\n", ntohs(id), ntohs(seq));
		break;
	case IPPROTO_TCP:
		ptr += hlen;
		tcph = (struct tcphdr *)ptr;  /* Get source and dest port */
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);
		ptr += sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		//port
		break;
	default:
		break;
	}

	if(scan_packet(src,dest,sport,dport) == 1)
	{
		printf("Packet allowed by firewall\n");
		printf("%s %s %d %d", src, dest, sport, dport);
		inject_packet(orgptr, len+14, is_incoming_to_eth1);
	}else{
		printf("Packet blocked by firewall\n");
	}
}


int identify_eth0_eth1(char* src){
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
		return 0;
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
		return 1;
	}
	return -1;


}
void inject_packet(char *ptr, int len, int is_incoming_to_eth1){
	printf("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");
	if(is_incoming_to_eth1 == 1){
		printf("Injecting on eth0\n");
		pcap_inject(pdeth0,ptr,len);
	}else if(is_incoming_to_eth1 == 0){
		printf("Injecting on eth1\n");
		pcap_inject(pdeth1,ptr,len);
	}else{
		printf("Not Injecting");
	}
}

void replace_destination_mac(struct ether_header *eptr, char* dest, int is_incoming_to_eth1){
	struct ether_addr *ether_d;
	int i;
	char *macptr = NULL;
	if((macptr = checkinArpTable(dest)) == NULL){
		macptr = arping(dest, is_incoming_to_eth1);
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

void replace_source_mac(struct ether_header *eptr, int is_incoming_to_eth1){
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
	char src[16], dest[16];

	iphdr = (struct ip*)(pkt_data+14);         /* Get IP header */

	hlen = iphdr->ip_hl * 4;
	strncpy(src, inet_ntoa(iphdr->ip_src), 16);
	strncpy(dest, inet_ntoa(iphdr->ip_dst), 16);
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
	char addip[16];
	strncpy(addip, ip, 16);

	char addmac[18];
	strncpy(addmac, mac, 18);

	time_t current;

	if (pthread_rwlock_rdlock(&lock) != 0) printf("can't get rdlock");
	HASH_FIND_STR(arptable, ip,t);
	pthread_rwlock_unlock(&lock);

	if(t == NULL){
		s = malloc(sizeof(struct my_struct));
		strncpy(s->ip, addip, 16);
		strncpy(s->val.mac, addmac, 18);
		gettimeofday(&tv,NULL);
		current = &tv.tv_sec;
		s->val.timestamp = current;
		if (pthread_rwlock_wrlock(&lock) != 0) printf("can't get wrlock");
        HASH_ADD_STR( arptable, ip, s );
        pthread_rwlock_unlock(&lock);
//		HASH_ADD_KEYPTR( hh, arptable, s->ip, strlen(s->ip), s );
		printf("Added ip %s in arp table\n", ip);
	}
	HASH_ITER(hh, arptable, u, tmp) {
			printf("After adding %s\n",u->ip);
			printf("After adding %s\n",u->val.mac);

	}

}

char* checkinArpTable(char* ip){
	struct my_struct *t, *s,*tmp;
	struct timeval tv;
	time_t current;
	time_t prev;
	char checkip[16];
	strncpy(checkip, ip, 16);
	HASH_ITER(hh, arptable, s, tmp) {
		printf("******%s\n",s->ip);
		printf("******%s\n",s->val.mac);
	}

	if (pthread_rwlock_rdlock(&lock) != 0) printf("can't get rdlock");
	HASH_FIND_STR(arptable, checkip,t);
	pthread_rwlock_unlock(&lock);

	if(t != NULL){
		gettimeofday(&tv,NULL);
		current = &tv.tv_sec;
		prev = t->val.timestamp;
		if(difftime(current, prev) > 60){
			printf("Deleting %s as this is stale\n", checkip);
			if (pthread_rwlock_wrlock(&lock) != 0) printf("can't get wrlock");
			HASH_DEL(arptable, t);  /* user: pointer to deletee */
			pthread_rwlock_unlock(&lock);
			free(t);
			return NULL;
		}else{
			printf("Already present ip - %s. returning it\n", checkip);
			return t->val.mac;
		}
	}
	printf("Not in arptable %s", checkip);
	return NULL;
}

char* arping(char* ip, int is_incoming_to_eth1){
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

