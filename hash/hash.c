#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "uthash.h"

typedef enum {SYN, SYNACK, ACK, FIN, FINACK, ENDACK} State;


struct my_struct {
    char key[45];                  /* key */
    State val;
    UT_hash_handle hh;         /* makes this structure hashable */
};
struct my_struct *statetable;

struct tuple
{
	char s_addr[16];
	char d_addr[16];
	u_int16_t s_port;
	u_int16_t d_port;
	State state;
};

int isAllowedByFirewall(){
	return 1;
}

int isSynPacket(){

}

int main(int argc,char *argv[])
{
	statetable = NULL;
	struct my_struct  *result, *s, *r, *tmp;
	struct tuple t;
	strncpy(t.s_addr, "225.225.225.225", 16);
	strncpy(t.d_addr, "1.1.1.1", 16);
	t.s_port = 65535;
	t.d_port = 1;
	t.state = SYN;

	char key[75];
	sprintf(key, "%s %s %d %d", t.s_addr, t.d_addr, t.s_port, t.d_port);
	printf("%s\n", key);
	int i;
	for( i= 0; i < 2; i++){
	HASH_FIND_STR(statetable,key, result);

	if(result != NULL){
		printf("Found");
		t.state = SYNACK;
		printf("%d", ENDACK);
		if(result->val >= ENDACK && t.state != SYN){
			printf("Ended");
			return 0;
		}
		if((result->val < ENDACK) && ((t.state - result->val) != 1)){
			printf("Some error in sequence");
			return 0;
		}
		r = malloc(sizeof(struct my_struct));
		strncpy(r->key,key, 75);
		r->val = t.state;
		HASH_DELETE(hh, statetable, result);
		HASH_ADD_STR(statetable,key, r);
		printf("Modified with state %d", r->val);
	}else{
		if(isAllowedByFirewall() == 0)
			return 0;
		if(t.state != SYN){
			printf("Not syn");
			return 0;
		}
		s = malloc(sizeof(struct my_struct));
		strncpy(s->key,key, 75);
		s->val = t.state;
		HASH_ADD_STR(statetable, key,s );
		printf("Added with state %d", s->val);
	}
	}


	return 0;

}
