#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
/* IP header */
struct ipheader {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src;  /* source and dest address */
        struct  in_addr ip_dst;
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
struct icmpheader {
    u_char  type;
    u_char  code;
    u_short checksum;
    u_short  id;
    u_short  seq;
    u_int   timestamp;
};

u_int16_t checksum(u_int8_t *buf,int len)  
{  
    u_int32_t sum=0;  
    u_int16_t *cbuf;  
  
    cbuf=(u_int16_t *)buf;  
  
    while(len>1)
    {  
        sum+=*cbuf++;  
        len-=2;  
    }  
  
    if(len)  
        sum+=*(u_int8_t *)cbuf;  
  
        sum=(sum>>16)+(sum & 0xffff);  
        sum+=(sum>>16);  
  
        return ~sum;  
}  
//伪造发送ping请求
void task22B(){

    char buffer[1024];
    int sockfd =socket(AF_INET,SOCK_RAW,IPPROTO_RAW);

    struct sockaddr_in target_addr;
    socklen_t len=sizeof(struct sockaddr);

    target_addr.sin_family = AF_INET;//ipv4
    target_addr.sin_addr.s_addr = inet_addr("10.0.2.131");

    int ip_len=84;
    struct ipheader *ip=(struct ipheader *)buffer;
    ip->ip_vhl=4<<4|20>>2;
    ip->ip_tos=0;
    ip->ip_len=84;
    ip->ip_id=htonl(0xdd25);
    ip->ip_off=0;
    ip->ip_ttl=64;
    ip->ip_p=1;//icmp
    ip->ip_sum=0;
    inet_aton("5.6.7.8",&ip->ip_src);
    inet_aton("10.0.2.131",&ip->ip_dst);
    ip->ip_sum=checksum((char*)ip,20);

    time_t now;
    time(&now);
    struct icmpheader *icmp=(struct icmpheader *) (buffer+sizeof(struct ipheader) );
    icmp->type=8;
    icmp->code=0;
    icmp->checksum=0;
    icmp->id=getpid();
    icmp->seq=1;
    icmp->timestamp=now;

    icmp->checksum=checksum((char *)icmp,64);
    
    sendto(sockfd,buffer,ip_len,0,(struct sockaddr * )&target_addr,len);
  
}
void task22A(){
    char buffer[1024];
    int sockfd =socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    struct sockaddr_in target_addr;
    socklen_t len=sizeof(struct sockaddr);

    target_addr.sin_family = AF_INET;//ipv4
    target_addr.sin_addr.s_addr = inet_addr("10.0.2.131");

    int ip_len=20;
    struct ipheader *ip=(struct ipheader *)buffer;
    ip->ip_vhl=4<<4|20>>2;
    ip->ip_tos=0;
    ip->ip_len=5;
    ip->ip_id=0;
    ip->ip_off=IP_DF | 0;
    ip->ip_ttl=124;
    ip->ip_p=1;//icmp
    ip->ip_sum=108;//?
    inet_aton("1.2.3.4",&ip->ip_src);
    inet_aton("10.0.2.131",&ip->ip_dst);

    int k=sendto(sockfd,buffer,ip_len,0,(struct sockaddr * )&target_addr,len);
    
  }

int main(){
    //task22A();
    task22B();
    //task21C():
return 0;
}