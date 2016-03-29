#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


//#define TEST

#ifdef TEST
#define ip_user_table "ip_conntrack_ip_user_table"
#define user_group_table "ip_conntrack_user_group_table"
#define ipuser_config "ip_user.conf"
#define usergroup_config "user_group.conf"
#else
#define ip_user_table "/proc/sys/net/ipv4/netfilter/ip_user_table"
#define user_group_table "/proc/sys/net/ipv4/netfilter/user_group_table"
#define ipuser_config "ip_user.conf"
#define usergroup_config "user_group.conf"
#endif

#define MAX_USERS 10000

struct ip_user_config{
	unsigned int ip;
	unsigned short uid;
};

struct user_group_config{
	unsigned short uid;
	unsigned short gid;
};

void write_user_group_table(){
	FILE *fin, *fout;
	char buf[32];
	char *uid, *gid;
	int cnt = 0;
	struct user_group_config ugconfig;
	fin = fopen(usergroup_config, "r");
	if (! fin )
		return;
	while (fgets(buf, 32, fin)){
		if (buf[0] == '\n' || buf[0] == '\0')
			continue;
		uid = strtok(buf, " ");
		gid = strtok(NULL, " ");
		if (uid && gid){
			ugconfig.uid = (unsigned short)atoi(uid);
			ugconfig.gid = (unsigned short)atoi(gid);
			printf("%u %u\n", ugconfig.uid, ugconfig.gid);
			fout = fopen(user_group_table, "wb");
			if (fout)
				fwrite(&ugconfig, sizeof(struct user_group_config), 1, fout);
			fclose(fout);
			cnt ++;
		}	
		memset(buf, 0, sizeof(buf));
		uid = gid = NULL;
		if (cnt >= MAX_USERS)
			break;
	}
	fclose(fin);
}

void write_ip_user_table(){
	FILE *fin, *fout;
	char buf[32];
	char *ip, *uid;
	int cnt = 0;
	struct ip_user_config iuconfig;
	
	fin = fopen(ipuser_config,"r");
	if (! fin)
		return;
	while (fgets(buf, 32, fin)){
		if (buf[0] == '\n' || buf[0] == '\0')
			continue;
		ip = strtok(buf, " ");
		uid = strtok(NULL, " ");
		if (ip && uid){
			inet_aton(ip, &iuconfig.ip);
			iuconfig.uid = (unsigned short)atoi(uid);
			printf("%x %u\n",iuconfig.ip, iuconfig.uid);
			fout = fopen(ip_user_table, "wb");
			if (fout)
				fwrite(&iuconfig, sizeof(struct ip_user_config), 1, fout);
			fclose(fout);
			cnt ++;
		}
		memset(buf, 0, sizeof(buf));
		ip = uid = NULL;
	}
	return;
}

void reload_signal(){
	system("echo 1 > /proc/sys/net/ipv4/netfilter/reload_userobj_config");
}

int main(void){
	reload_signal();
	write_user_group_table();
	write_ip_user_table();
	return 0;	
}
