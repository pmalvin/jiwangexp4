#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#define MAX_ROUTE 256
#define MAX_ARP 256
#define MAX_DEVICE 256
#define BUF_SIZE 1024
struct route_item{
    char destination[16];
    char gateway[16];
    char netmask[16];
    char interface[16];
}route_info[MAX_ROUTE];
int route_num = 0;

struct arp_table_item{
    char ip_addr[16];
    char mac_addr[18];
}arp_map[MAX_ARP];
int arp_num = 0;

struct device_item{
    char interface[16];
    char mac_addr[18];
}device[MAX_DEVICE];
int device_num = 0;

void init();
void ip_byte2str(char* dest,unsigned char* byte_ip);
void mac_str2byte(unsigned char* dest,char* str_mac);
void ip_str2byte(unsigned char* dest, char* str_ip);
int get_route_index(unsigned char* dest_ip);
int get_arp_index(int route_index);
int get_device_index(int route_index);

int main()
{
    init();
    int sockfd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    int n_read;
    char buffer[BUF_SIZE];
    char send_buf[BUF_SIZE];
    char *eth_head;
    char *ip_head;
    unsigned char *src_mac;//6 bytes
    unsigned char *dest_mac;//6 bytes
    unsigned char *src_ip;//4 bytes
    unsigned char *dest_ip; //4 bytes
    while(1)
    {
        memset(buffer,0,sizeof(buffer));
        memset(send_buf,0,sizeof(send_buf));
        n_read = recvfrom(sockfd,buffer,2048,0,NULL,NULL);
        if(n_read < 42)
        {
            printf("error when recv msg");
            return -1;
        }
        memcpy(send_buf,buffer,sizeof(send_buf));
        eth_head = send_buf;
        dest_mac = eth_head;
        src_mac = dest_mac + 6;
        ip_head = eth_head + 14;
        src_ip = ip_head + 12;
        dest_ip = src_ip + 4;
        int route_index = get_route_index(dest_ip);
        int arp_index = get_arp_index(route_index);
        int device_index = get_device_index(route_index);
        mac_str2byte(dest_mac,arp_map[arp_index].mac_addr);
        mac_str2byte(src_mac,device[device_index].mac_addr);
        int size = send(sockfd,send_buf,sizeof(send_buf),0);
    }
    return 0;
}

void init()//initialization of tables and maps
{
    strcpy(route_info[0].destination,"192.168.3.0");
    strcpy(route_info[0].gateway,"192.168.2.31");
    strcpy(route_info[0].netmask,"255.255.255.0");
    strcpy(route_info[0].interface,"eth6");
    strcpy(route_info[1].destination,"192.168.1.0");
    strcpy(route_info[1].gateway,"192.168.1.30");
    strcpy(route_info[1].netmask,"255.255.255.0");
    strcpy(route_info[1].interface,"eth8");
    strcpy(arp_map[0].ip_addr,"192.168.1.30");
    strcpy(arp_map[0].mac_addr,"08:00:27:5B:5F:E0");
    strcpy(arp_map[1].ip_addr,"192.168.2.31");
    strcpy(arp_map[1].mac_addr,"08:00:27:64:6B:B2");
    strcpy(device[0].interface,"eth6");
    strcpy(device[0].mac_addr,"08:00:27:55:D1:54");
    strcpy(device[1].interface,"eth8");
    strcpy(device[1].mac_addr,"08:00:27:45:9A:C2");
}
void initexp3()
{
    strcpy(route_info[0].destination,"192.168.3.0");
    strcpy(route_info[0].gateway,"192.168.3.31");
    strcpy(route_info[0].netmask,"255.255.255.0");
    strcpy(route_info[0].interface,"eth8");
    strcpy(route_info[1].destination,"192.168.1.0");
    strcpy(route_info[1].gateway,"192.168.2.30");
    strcpy(route_info[1].netmask,"255.255.255.0");
    strcpy(route_info[1].interface,"eth6");
    strcpy(arp_map[0].ip_addr,"192.168.2.30");
    strcpy(arp_map[0].mac_addr,"08:00:27:55:D1:54");
    strcpy(arp_map[1].ip_addr,"192.168.3.31");
    strcpy(arp_map[1].mac_addr,"08:00:27:9E:E3:FA");
    strcpy(device[0].interface,"eth6");
    strcpy(device[0].mac_addr,"08:00:27:64:6B:B2");
    strcpy(device[1].interface,"eth8");
    strcpy(device[1].mac_addr,"08:00:27:6D:6D:72");
}
void ip_byte2str(char* dest,unsigned char* byte_ip)
{
    sprintf(dest,"%d.%d.%d.%d",byte_ip[0],byte_ip[1],byte_ip[2],byte_ip[3]);
}
void ip_str2byte(unsigned char* dest, char* str_ip)
{
	unsigned a,b,c,d;
    sscanf(str_ip,"%d.%d.%d.%d",&a,&b,&c,&d);
	*(unsigned int *)dest = (a << 24) + (b << 16) + (c << 8) + d;
}
void mac_str2byte(unsigned char* dest,char* str_mac)
{
	unsigned a,b,c,d,e,f;
    sscanf(str_mac,"%x:%x:%x:%x:%x:%x",&a,&b,&c,&d,&e,&f);
	*(unsigned long*)dest = ((unsigned long)a << 40) + ((unsigned long)b << 32) + (c<<24) + (d<<16) + (e << 8) + f;
}
int get_route_index(unsigned char* dest_ip_byte)
{
    int i;
    for(i = 0;i<route_num;i++)
    {   
        unsigned mask;
        ip_str2byte((unsigned char*)&mask,route_info[i].netmask);
        unsigned item_ip_byte;
        ip_str2byte((unsigned char*)&item_ip_byte,route_info[i].destination);
        unsigned pattern = item_ip_byte & mask;
        unsigned trimmed_dest_ip = *(unsigned*)dest_ip_byte & mask;
        if(pattern == trimmed_dest_ip)
        { 
            return i;
        }
    }
    return -1;
}

int get_arp_index(int route_index)
{
    int i;
    for(i=0;i<arp_num;i++)
    {
        if(strcmp(route_info[route_index].netmask,arp_map[i].ip_addr) == 0)
        { 
            return i;
        }
    }
    return -1;
}
int get_device_index(int route_index)
{
    int i;
    for(i=0;i<arp_num;i++)
    {
        if(strcmp(route_info[route_index].interface,device[i].interface) == 0)
        { 
            return i;
        }
    }
    return -1;
}
