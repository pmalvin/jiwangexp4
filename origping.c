#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <string.h>

#define MAX_PKT_NUM 10
typedef struct ping_packet_status
{
    struct timeval begin_time;//time when request sent
    struct timeval end_time;//time when reply received
    int seq;
}ping_packet_status;//used to summarize
ping_packet_status ping_packet[MAX_PKT_NUM];
pid_t pid;
struct sockaddr_in dest;
int sockfd;
int send_count;

void icmp_gen(struct icmp* header, int seq, int len);//Generate icmp data
unsigned short calc_cksum(unsigned short *addr,int len);//calculate cksum
int icmp_resolve(char* buf,int len);
struct timeval cal_time_offset(struct timeval begin, struct timeval end);
void send_ping();
void recv_ping();
int main(int argc, char **argv)
{
    int size = 128*1024;//128k
    char dest_addr_str[80];
    memset(dest_addr_str,0,80);
    unsigned inaddr = 1;
    printf("Enter ip:");
    scanf("%s",dest_addr_str);
    sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(sockfd < 0)
    {
        printf("Fail to create socket!\n");
        return -1;
    }
    
    pid = getpid();//will be used as id
    
    bzero(&dest,sizeof(dest));
    
    dest.sin_family = AF_INET;
    
    inaddr = inet_addr(dest_addr_str);//resolve destination ip addr
    memcpy((char*)&dest.sin_addr,&inaddr,sizeof(inaddr));//set destination addr
    printf("PING %s...\n",dest_addr_str);
    while(send_count < MAX_PKT_NUM)
    {
        send_ping();
        recv_ping();
        sleep(1);
    }
    close(sockfd);
    return 0;
}
void icmp_gen(struct icmp* header, int seq, int len)
{
    int i;
    
    header->icmp_type = ICMP_ECHO; //Echo request
    header->icmp_code = 0;
    header->icmp_cksum = 0;//will be generated later
    header->icmp_seq = seq;//1,2,3,4,...
    header->icmp_id = pid & 0xffff;//use pid
    for(i = 0;i < len;i++)//fill data
    {
        header->icmp_data[i] = i;
    }
    header->icmp_cksum = calc_cksum((unsigned short*)header,len);//generate checksum
}
unsigned short calc_cksum(unsigned short *addr,int len)
{
    unsigned sum = 0;
    unsigned short *w = addr;
    unsigned short cksum = 0;//result
    while(len>1)
    {
        sum+=*w++;
        len-=2;
    }
    if(len == 1)//if one byte left, expand it to 2 bytes
    {
        unsigned short temp = 0x00;
        memcpy((unsigned char*)&temp + 1,w,1);//this virtual machine is little edian
        sum += temp;
    }
    sum = (sum>>16)+(sum & 0xffff);
    sum += (sum >> 16);
    cksum = ~sum;
    return cksum;
}
int icmp_resolve(char* buf,int len)
{
    struct timeval begin_time, recv_time,offset_time/*time interval*/;
    double rtt;//round trip time
    struct ip* ip_hdr = (struct ip*)buf;
    int iphdr_len = ip_hdr->ip_hl * 4;
    struct icmp* icmp = (struct icmp*)(buf + iphdr_len);//point to icmp head
    len -= iphdr_len;//length of icmp
    if(len<8)
    {
        printf("Invalid length of icmp packet!\n");
        return -1;
    }
    
    //tell whether it is an echo reply to the packet we sent
    if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == (pid&0xffff)))
    {
        //if seq is out of range,return
        if((icmp->icmp_seq < 0) || (icmp->icmp_seq > MAX_PKT_NUM))
        {
            printf("icmp packet seq out of range!\n");
            return -1;
        }
        //calc time interval
        begin_time = ping_packet[icmp->icmp_seq].begin_time;
        gettimeofday(&recv_time,NULL);
        
        offset_time = cal_time_offset(begin_time,recv_time);
        rtt = offset_time.tv_sec * 1000 + offset_time.tv_usec/1000.0;//convert to ms
        printf("%d byte from %s: icmp_seq = %u rtt=%.2f ms\n",
            len,inet_ntoa(ip_hdr->ip_src),icmp->icmp_seq,rtt);
    }
    else
    {
        printf("invalid icmp packet!\n");
        return -1;
    }
    return 0;
}

/*calc the difference between two timevals*/
struct timeval cal_time_offset(struct timeval begin, struct timeval end)
{
    struct timeval ret;
    ret.tv_sec = end.tv_sec - begin.tv_sec;
    ret.tv_usec = end.tv_usec - begin.tv_usec;
    if(ret.tv_usec < 0)
    {
        ret.tv_sec--;
        ret.tv_usec += 1e6;
    }
    return ret;
}

void send_ping()
{
    char send_buf[128];
    memset(send_buf,0,sizeof(send_buf));//initialization
    int size = 0;
    gettimeofday(&(ping_packet[send_count].begin_time),NULL);//set begin time
    icmp_gen((struct icmp*)send_buf,send_count,64);//generate icmp packet
    size = sendto(sockfd,send_buf,64,0,(struct sockaddr*)&dest,sizeof(dest));//send icmp packet
    send_count++;
}

void recv_ping()
{
    char recv_buf[512];
    memset(recv_buf,0,sizeof(recv_buf));//initialize buffer
    int size = recv(sockfd,recv_buf,sizeof(recv_buf),0);//receive reply
    if(size < 0)
    {
        printf("Receive data failed!");
        return;
    }
    int ret = icmp_resolve(recv_buf,size);
    if(ret == -1)//drop packet if it doesn't belong to us
    {
        return;
    }
}