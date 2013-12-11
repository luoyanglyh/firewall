#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/in_systm.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
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

typedef enum {SYN, SYNACK, ACK, FIN, FINACK, ENDACK, OTHER} State;

void capture_packet_eth0();
void capture_packet_eth1();
int scan_packet(char *src,char *dest,u_int16_t sport,u_int16_t dport, u_int8_t protocol, State state);
int  replace_destination_mac(struct ether_header *eptr, char* dest, int is_incoming_to_eth1);
void replace_source_mac(struct ether_header *eptr, int is_incoming_to_eth1);
void inject_packet(struct ether_header *ptr, int len, int is_incoming_to_eth1);
char* arping(char* ip, int is_incoming_to_eth1);
int identify_eth0_eth1(char* src);
char* checkinArpTable(char* ip);
void addinArpTable(char*ip, char*mac);
void readrulesfile(char *rule_file);
int isAllowedByFirewall(char *src,char *dest,u_int16_t sport,u_int16_t dport);
void send_reset_tcp_packet(char* src_ip, char* dst_ip, u_int16_t src_prt, u_int16_t dst_prt);
void send_reset_icmp_packet(char* src_ip, char* dst_ip);
State getState(struct tcphdr *tcph);

char* ETH0 = "eth0";
char* ETH1 = "eth1";
char* ETH0_MAC = "00:0c:29:7b:00:69";
char* ETH1_MAC = "00:0c:29:7b:00:73";
char* ETH0_IP = "30.10.1.128";
char* ETH1_IP = "20.10.1.128";
typedef struct filtering_rules file_record;

pcap_t *pdeth0;          /* packet capture struct pointer */
pcap_t *pdeth1;          /* packet capture struct pointer */
char* offline_file;
char* rules_file;
struct arp_struct *arptable;
pthread_rwlock_t lock;

struct arpvalue {
	char mac[18];
	time_t timestamp;
};

struct filtering_rules {
	uint32_t s_addr_start;
	uint32_t s_addr_end;

	uint32_t d_addr_start;
	uint32_t d_addr_end;

	u_int16_t s_port_start;
	u_int16_t s_port_end;

	u_int16_t d_port_start;
	u_int16_t d_port_end;

	int decision;
};

struct rule_struct {
    struct filtering_rules  key;                  /* key */
    int  decision;
    UT_hash_handle hh;         /* makes this structure hashable */
};
struct rule_struct *ruletable;

struct state_struct {
    char key[45];                  /* key */
    State val;
    UT_hash_handle hh;         /* makes this structure hashable */
};
struct state_struct *statetable;

struct arp_struct {
    char ip[16];                    /* key */
    struct arpvalue val;
    UT_hash_handle hh;         /* makes this structure hashable */
};

int main(int argc,char *argv[]) {
	arptable = NULL;    /* important! initialize to NULL */
    int err;
    pthread_t tid[2];
	char errbuf[PCAP_ERRBUF_SIZE];


    if (pthread_rwlock_init(&lock,NULL) != 0) printf("can't create rwlock");

	if(argc <= 1){
		printf("Enter the arguments\n");
		return 1;
	}

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
	readrulesfile(rules_file);

	if ((pdeth0 = pcap_open_live(ETH0, BUFSIZ, 0, 0, errbuf)) == NULL)
	{
		printf("Error opening device: %s", errbuf);
	}

	printf("Handle for Device = %s", ETH1);
	if ((pdeth1 = pcap_open_live(ETH1, BUFSIZ, 1, 0, errbuf)) == NULL)
	{
		printf("Error opening device: %s", errbuf);
	}

	err = pthread_create((tid + 0), NULL, capture_packet_eth1, (void *) 0);
	if (err != 0)
		printf("\ncan't create thread :[%s]", strerror(err));
	else
		printf("\n Thread created successfully\n");

	err = pthread_create((tid + 1), NULL, capture_packet_eth0, (void *) 1);
	if (err != 0)
		printf("\ncan't create thread :[%s]", strerror(err));
	else
		printf("\n Thread created successfully\n");

	pthread_join((tid[0]), NULL);
	pthread_join((tid[1]), NULL);

	pthread_exit(NULL);
	return(0);
}

void capture_loop(pcap_t* pd, int packets, pcap_handler func) {
    int linktype;

    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(pd)) < 0)
    {
        printf("pcap_datalink(): %s\n", pcap_geterr(pd));
        return;
    }

    // Set the datalink layer header size.
    switch (linktype)
    {
    case DLT_NULL:
        break;

    case DLT_EN10MB:
    	break;

    case DLT_SLIP:
    case DLT_PPP:
        break;

    default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }

    // Start capturing packets.
    if (pcap_loop(pd, packets, func, 0) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pd));
}

void capture_packet_eth0() {
    capture_loop(pdeth0, -1, (pcap_handler)parse_packet);
}

void capture_packet_eth1() {
    capture_loop(pdeth1, -1, (pcap_handler)parse_packet);
}

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr){
	struct ether_header *orgeptr;
    struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256], src[256], dest[256];
    unsigned short id, seq;
    char srcmac[18], dstmac[18];
    u_int16_t srcport, dstport;
    int scanpacket;

    orgeptr = (struct ether_header *) packetptr;
    strncpy(srcmac, ether_ntoa((struct ether_addr *)&orgeptr->ether_shost),18);
    strncpy(dstmac, ether_ntoa((struct ether_addr *)&orgeptr->ether_dhost), 18);

    // Skip the datalink layer header and get the IP header fields.
    packetptr += 14;
    iphdr = (struct ip*)packetptr;
    strcpy(src, inet_ntoa(iphdr->ip_src));
    strcpy(dest, inet_ntoa(iphdr->ip_dst));


	int is_incoming_to_eth1 = identify_eth0_eth1(src);
	printf("Found is_incoming_to_eth1 as %d\n", is_incoming_to_eth1);
	if(is_incoming_to_eth1 == -1){
		return;
	}

	if(is_incoming_to_eth1 == 1){
		printf("On %s ", ETH1);
	}else{
		printf("On %s ", ETH0);
	}
	printf("Timestamp: %d\n",(int)time(NULL));
	printf("ID = %d\n", iphdr->ip_id);
	printf("Before srcip: %s srcmac: %s dstip: %s dstmac: %s\n",
					src,srcmac,dest,dstmac );

    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
        printf("TCP %s:%d -> %s:%d\n", src, ntohs(tcphdr->source),
               dest, ntohs(tcphdr->dest));
        printf("%s\n", iphdrInfo);
        srcport = tcphdr->source;
        dstport = tcphdr->dest;
        printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window), 4*tcphdr->doff);
        State state = getState(tcphdr);
        scanpacket = scan_packet(src,dest,srcport,dstport, IPPROTO_TCP, state);
        break;

    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;
        printf("UDP %s:%d -> %s:%d\n", src, ntohs(udphdr->source),
               dest, ntohs(udphdr->dest));
        printf("%s\n", iphdrInfo);
        srcport = udphdr->source;
        dstport = udphdr->dest;
        scanpacket = scan_packet(src,dest,srcport,dstport, IPPROTO_UDP, SYN);
        break;

    case IPPROTO_ICMP:
        icmphdr = (struct icmphdr*)packetptr;
        printf("ICMP %s -> %s\n", src, dest);
        printf("%s\n", iphdrInfo);
        memcpy(&id, (u_char*)icmphdr+4, 2);
        memcpy(&seq, (u_char*)icmphdr+6, 2);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code,
               ntohs(id), ntohs(seq));
        scanpacket = scan_packet(src,dest,1,1, IPPROTO_ICMP, SYN);
        break;
    }

    if(scanpacket == 2){
    	printf("Packet rejected by firewall\n");
    	if(iphdr->ip_p == IPPROTO_UDP || iphdr->ip_p == IPPROTO_ICMP){
    		if(is_incoming_to_eth1){
    			send_reset_icmp_packet(ETH1, src);
    		}else{
    			send_reset_icmp_packet(ETH0, src);
    		}
    	}else if(iphdr->ip_p == IPPROTO_TCP){
    		send_reset_tcp_packet(dest,src, dstport, srcport);
    	}
    	return;
    }else if(scanpacket == 1){
		if(replace_destination_mac(orgeptr, dest,is_incoming_to_eth1) == -1 ) {
			printf(" Error in replacing destination!\n");
			return;
		}

		//replace source MAC
		replace_source_mac(orgeptr,is_incoming_to_eth1);

		strncpy(srcmac, ether_ntoa((struct ether_addr *)&orgeptr->ether_shost), 18);
		strncpy(dstmac, ether_ntoa((struct ether_addr *)&orgeptr->ether_dhost), 18);

		if(is_incoming_to_eth1 == 1){
			printf("On %s ", ETH1);
		}else{
			printf("On %s ", ETH0);
		}
	    printf("Timestamp: %d\n",(int)time(NULL));
		printf("ID = %d\n", iphdr->ip_id);
		printf("After srcip: %s srcmac: %s dstip: %s dstmac: %s\n",
					src,srcmac,dest,dstmac);

		inject_packet(orgeptr, packethdr->len, is_incoming_to_eth1);
    	scanpacket = 0;
    }else{
    	printf("Packet blocked by firewall\n");
    	return;
    }
    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
}

int identify_eth0_eth1(char* src){
	int i =0, dot_count = 0;
	printf("identify_eth0_eth1 for %s\n", src);
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
void inject_packet(struct ether_header *ptr, int len, int is_incoming_to_eth1){
	if(is_incoming_to_eth1 == 1){
		printf("Injecting on eth0\n");
		pcap_inject(pdeth0,ptr,len);
	}else if(is_incoming_to_eth1 == 0){
		printf("Injecting on eth1\n");
		pcap_inject(pdeth1,ptr,len);
	}else{
		printf("Not Injecting\n");
	}
}

int  replace_destination_mac(struct ether_header *eptr, char* dest, int is_incoming_to_eth1){
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
		if(macptr != NULL){
			for( i = 0; i < 6; i++){
				eptr->ether_dhost[i] = (u_int8_t)(ether_d->ether_addr_octet[i]);
			}
			return 1;
		}
	}
	return -1;
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

State getState(struct tcphdr *tcph) {
	if(tcph->fin){
		printf("State is fin\n");
		return FIN;
	}

	if(tcph->syn && tcph->ack){
		printf("State is synack\n");
		return SYNACK;
	}
	if(tcph->syn){
		printf("State is syn\n");
		return SYN;
	}
	if(tcph-> ack){
		printf("State is ack\n");
		return ACK;
	}
	return OTHER;
}

void dispatcher_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	int hlen;
	struct ip *iphdr;
	char src[16], dest[16];
	struct tcphdr *tcph;
	struct icmphdr *icmph;
	struct udphdr *udph;
	u_int16_t sport,dport;
	const struct pcap_pkthdr *orgheader = header;
	const u_char *org_pkt_data = pkt_data;

	iphdr = (struct ip*)(pkt_data+14);         /* Get IP header */

	hlen = iphdr->ip_hl * 4;
	strncpy(src, inet_ntoa(iphdr->ip_src), 16);
	strncpy(dest, inet_ntoa(iphdr->ip_dst), 16);
	pkt_data +=14;
	pkt_data += hlen;
	int firewall_decision;
	switch(iphdr->ip_p){
	case IPPROTO_ICMP:
		icmph = (struct icmphdr *)pkt_data;
		sport = 1;
		dport = 1;
		firewall_decision = scan_packet(src,dest,sport,dport, IPPROTO_ICMP, OTHER);
		if(firewall_decision == 1 ) {
			printf("Writing this to pacap");
			pcap_dump(dumpfile,orgheader,org_pkt_data);
		}else if(firewall_decision == 2){
			printf("create new packet");

		}
		break;
	case IPPROTO_TCP:
		tcph = (struct tcphdr *)pkt_data;  /* Get source and dest port */
		sport = ntohs(tcph->source);
		dport = ntohs(tcph->dest);
		pkt_data += sizeof(struct tcphdr);
//			save the packet on the dump file
		State state = getState(tcph);
		firewall_decision = scan_packet(src,dest, sport,dport, IPPROTO_TCP, state);
		if(firewall_decision== 1){
			printf("Writing this to pacap");
			pcap_dump(dumpfile,orgheader,org_pkt_data);
		}else if(firewall_decision == 2){
			printf("create new packet");
		}
		break;
	case IPPROTO_UDP:
		udph = (struct udphdr *)pkt_data;
		sport = udph->source;
		dport = udph->dest;
		firewall_decision = scan_packet(src,dest,sport,dport, IPPROTO_UDP, OTHER) ;
		if(firewall_decision == 1 ) {
			printf("Writing this to pacap");
			pcap_dump(dumpfile,orgheader,org_pkt_data);
		}
		break;
	default:
		break;
	}

}

void addinArpTable(char*ip, char*mac){
	struct arp_struct *t, *s, *u, *tmp;
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
		s = malloc(sizeof(struct arp_struct));
		strncpy(s->ip, addip, 16);
		strncpy(s->val.mac, addmac, 18);
		gettimeofday(&tv,NULL);
		current = &tv.tv_sec;
		s->val.timestamp = current;
		if (pthread_rwlock_wrlock(&lock) != 0) printf("can't get wrlock");
        HASH_ADD_STR( arptable, ip, s );
        pthread_rwlock_unlock(&lock);
		printf("Added ip %s in arp table\n", ip);
	}
	HASH_ITER(hh, arptable, u, tmp) {
			printf("After adding %s\n",u->ip);
			printf("After adding %s\n",u->val.mac);

	}

}

char* checkinArpTable(char* ip){
	struct arp_struct *t;
	struct timeval tv;
	time_t current;
	time_t prev;
	char checkip[16];
	strncpy(checkip, ip, 16);

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
	printf("Not in arptable %s\n", checkip);
	return NULL;
}

char* arping(char* ip, int is_incoming_to_eth1){
	printf("arpinging with %d", is_incoming_to_eth1);
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
		printf("mac is null\n");
	return macptr;
}

void readrulesfile(char *rules_file){
	FILE *fp;
	char firstarg[40];
	char thirdarg[40];
	char secondarg[40];
	char fortharg[40];
	int dec = 0;

	fp = fopen(rules_file,"r");
	file_record frecord;
	char* index;
	struct rule_struct  *result, *s;
	rewind(fp);
	while(!feof(fp)) {

		fscanf(fp,"%s %s %s %s %d", firstarg, secondarg, thirdarg, fortharg, &dec);
		frecord.s_addr_start = inet_addr(strtok (firstarg,"-"));
		index = strtok (NULL,"-");
		if(index != NULL){
			frecord.s_addr_end = inet_addr(index);
		}else{
			frecord.s_addr_end = frecord.s_addr_start;
		}

		frecord.d_addr_start = inet_addr(strtok (secondarg,"-"));
		index = strtok (NULL,"-");
		if(index != NULL){
			frecord.d_addr_end = inet_addr(index);
		}else{
			frecord.d_addr_end = frecord.d_addr_start;
		}

		frecord.s_port_start = atoi(strtok (thirdarg,"-"));
		index = strtok (NULL,"-");
		if(index != NULL){
			frecord.s_port_end = atoi(index);
		}else{
			frecord.s_port_end = frecord.s_port_start;
		}

		frecord.d_port_start = atoi(strtok (fortharg,"-"));
		index = strtok (NULL,"-");
		if(index != NULL){
			frecord.d_port_end = atoi(index);
		}else{
			frecord.d_port_end = frecord.d_port_start;
		}

		frecord.decision = dec;

		HASH_FIND(hh, ruletable, &frecord, sizeof(file_record), result);
		if(result == NULL){
			s = malloc(sizeof(struct rule_struct));
			s->key = frecord;
			s->decision = dec;
			HASH_ADD(hh, ruletable, key, sizeof(file_record), s);
		}

	}
	fclose(fp);
}

int isAllowedByFirewall(char *src,char *dest,u_int16_t sport,u_int16_t dport){
	    uint32_t sip = inet_addr(src);
		uint32_t dip = inet_addr(dest);
		struct rule_struct  *s, *tmp;

		HASH_ITER(hh, ruletable, s, tmp) {
//				printf("******%u\n",s->key.s_addr_start);
//				printf("******%u\n",s->key.s_addr_end);
//				printf("******%u\n",s->key.d_addr_start);
//				printf("******%u\n",s->key.d_addr_end);
//				printf("******%u\n",s->key.s_port_start);
//				printf("******%u\n",s->key.s_port_end);
//				printf("******%u\n",s->key.d_port_start);
//				printf("******%u\n",s->key.d_port_end);
//				printf("******%d\n",s->decision);
				if(sip >= s->key.s_addr_start && sip <= s->key.s_addr_end){
					printf("Source matched");
					if(dip >= s->key.d_addr_start && dip <= s->key.d_addr_end){
						printf("Dest matched");
						if(sport >= s->key.s_port_start && sport <= s->key.s_port_end){
							printf("sport matched");
							if(dport >= s->key.d_port_start && dport <= s->key.d_port_end){
								printf("Dest mathced");
								return s->decision;
							}
						}
					}
				}
		}
		return 0;
}

int scan_packet(char *src,char *dest,u_int16_t sport,u_int16_t dport, u_int8_t protocol, State state) {
	struct state_struct  *result, *s, *r;
	char key1[75], key2[75];
	// check for both
	sprintf(key2, "%s %s %d %d", dest, src, dport, sport);
	sprintf(key1, "%s %s %d %d", src, dest, sport, dport);

	HASH_FIND_STR(statetable,key1, result);

	if(result == NULL){
		HASH_FIND_STR(statetable,key2, result);
		if(result == NULL){
			int firewall_decision = isAllowedByFirewall(src, dest, sport, dport);
			if( firewall_decision != 1)
				return firewall_decision;
			if(protocol == IPPROTO_TCP && state != SYN){
				printf("Not syn\n");
				return 0;
			}
			s = malloc(sizeof(struct state_struct));
			strncpy(s->key,key1, 75);
			s->val = state;
			HASH_ADD_STR(statetable, key,s );
			printf("Added with state %d\n", s->val);
			return 1;
		}else{
			printf("Found key 2\n");
			if(protocol == IPPROTO_ICMP || protocol == IPPROTO_UDP){
				return 1;
			}
			if(result->val == FIN && state == FIN){
				state = FINACK;
			}
			if(result->val == FINACK && state == ACK){
				state = ENDACK;
			}

			if(result->val >= ENDACK){
				// remove from hashtable
				HASH_DELETE(hh, statetable, result);
				printf("Ended\n");
				return 0;
			}

			r = malloc(sizeof(struct state_struct));
			strncpy(r->key,key2, 75);
			r->val = state;
			HASH_DELETE(hh, statetable, result);
			HASH_ADD_STR(statetable,key, r);
			printf("Modified with state %d\n", r->val);
			return 1;
		}

	}else{
		printf("Found key 1\n");
		if(protocol == IPPROTO_ICMP || protocol == IPPROTO_UDP){
			return 1;
		}
		if(result->val == FIN && state == FIN){
			state = FINACK;
		}
		if(result->val == FINACK && state == ACK){
			state = ENDACK;
		}
		if(result->val >= ENDACK){
			// remove from hashtable
			HASH_DELETE(hh, statetable, result);
			printf("Ended\n");
			return 0;
		}

		r = malloc(sizeof(struct state_struct));
		strncpy(r->key,key1, 75);
		r->val = state;
		HASH_DELETE(hh, statetable, result);
		HASH_ADD_STR(statetable,key, r);
		printf("Modified with state %d\n", r->val);
		return 1;
	}

}

unsigned short csum (unsigned short *buf, int nwords) {
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

void send_reset_icmp_packet(char* src_ip, char* dst_ip){
		printf("send_reset_icmp_packet Called");
	  int s = socket (PF_INET, SOCK_RAW, IPPROTO_ICMP);	/* open raw socket */
	  char datagram[4096];
	  struct ip *iph = (struct ip *) datagram;
	  struct icmphdr *icmph = (struct icmphdr *) (datagram + sizeof (struct ip));
	  struct sockaddr_in sin;

	  sin.sin_family = AF_INET;
	  sin.sin_addr.s_addr = inet_addr (dst_ip);

	  memset (datagram, 0, 4096);	/* zero out the buffer */

	  iph->ip_hl = 5;
	  iph->ip_v = 4;
	  iph->ip_tos = 0;
	  iph->ip_len = sizeof (struct ip) + sizeof (struct icmphdr);	/* no payload */
	  iph->ip_ttl = 255;
	  iph->ip_p = IPPROTO_ICMP;
	  iph->ip_sum = 0;
	  iph->ip_src.s_addr = inet_addr (src_ip);
	  iph->ip_dst.s_addr = sin.sin_addr.s_addr;
	  iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len >> 1);

	  icmph->code = 13;
	  icmph->type = 3;
	  icmph->checksum = csum ((unsigned short *) icmph, sizeof(struct icmphdr));
	  {
	    int one = 1;
	    const int *val = &one;
	    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	      printf ("Warning: Cannot set HDRINCL!\n");
	  }
	  if (sendto (s, datagram, iph->ip_len,	0,(struct sockaddr *) &sin,	sizeof (sin)) < 0)
		  printf ("error\n");
}

void send_reset_tcp_packet(char* src_ip, char* dst_ip, u_int16_t src_prt, u_int16_t dst_prt){
	  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);	/* open raw socket */
	  char datagram[4096];
	  struct ip *iph = (struct ip *) datagram;
	  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	  struct sockaddr_in sin;
	  sin.sin_family = AF_INET;
	  sin.sin_port = htons (dst_prt);
	  sin.sin_addr.s_addr = inet_addr (dst_ip);

	  memset (datagram, 0, 4096);	/* zero out the buffer */

	  iph->ip_hl = 5;
	  iph->ip_v = 4;
	  iph->ip_tos = 0;
	  iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);	/* no payload */
	  iph->ip_ttl = 255;
	  iph->ip_p = 6;
	  iph->ip_sum = 0;
	  iph->ip_src.s_addr = inet_addr (src_ip);
	  iph->ip_dst.s_addr = sin.sin_addr.s_addr;
	  iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len >> 1);

	  tcph->doff = 5;
	  tcph->source = htons (src_prt);
	  tcph->dest = htons (dst_prt);
	  tcph->ack_seq = htonl(1);
	  tcph->seq = htonl(0);
	  tcph->ack = 1;
	  tcph->rst = 1;
	  tcph->window = htonl (10);
	  tcph->check = csum ((unsigned short *) tcph, sizeof(struct tcphdr));
	  {
	    int one = 1;
	    const int *val = &one;
	    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	      printf ("Warning: Cannot set HDRINCL!\n");
	  }
	  if (sendto (s, datagram, iph->ip_len,	0,(struct sockaddr *) &sin,	sizeof (sin)) < 0)
		  printf ("error\n");
}

