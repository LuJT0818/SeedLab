#include <iostream>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

using namespace std;
// g++ -o spoofing spoofing.cpp -lpcap

int sd;
char buffer[1024];

unsigned short checksum(void *buf, int len) {
    unsigned short *p = (unsigned short *)buf;
    unsigned int sum = 0;
    while(len > 1) {
        sum += *p++;
        len -= 2;
    }
    if(len == 1) {
        sum += *(unsigned char *)p;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = ~sum;
    return sum;
}
void make_icmp_header(struct icmp *icmp_hdr){
    int icmp_len = 8 + 56;                 // ICMP 头 8 字节 + 载荷 56 字节
    icmp_hdr->icmp_type = ICMP_ECHO;       // type=8
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id   = htons(getpid() & 0xFFFF);
    icmp_hdr->icmp_seq  = htons(1);
    memset(buffer + sizeof(struct ip) + 8, 'A', 56);  // 载荷
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = checksum(icmp_hdr, icmp_len);
}

void make_ip_header(struct ip *ip_hdr, char *src_ip, char *dst_ip, int icmp_len){ 
    ip_hdr->ip_v   = 4;
    ip_hdr->ip_hl  = 5;                    // 5 * 4 = 20 字节
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + icmp_len);  // 总长度
    ip_hdr->ip_id  = htons(54321);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p   = IPPROTO_ICMP;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));
    inet_pton(AF_INET, src_ip, &ip_hdr->ip_src);
    inet_pton(AF_INET, dst_ip, &ip_hdr->ip_dst);
}
int main(){
    char src_ip[16] = "10.9.0.5";
    char dst_ip[16] = "10.9.0.6";
    struct ip *ip_hdr = (struct ip *)buffer;
    struct icmp *icmp_hdr = (struct icmp *)(buffer + sizeof(struct ip));
    // 1. 创建原始套接字: IPPROTO_RAW 缓冲区已经包含完整IP头部，内核不要再追加IP头
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) {
        perror("socket() error");
        exit(-1);
    }

    // 在buffer中手动组装IP头、ICMP/TCP/UDP头部、载荷；注意网络字节序
    make_icmp_header(icmp_hdr);
    int icmp_len = 8 + 56;
    make_ip_header(ip_hdr, src_ip, dst_ip, icmp_len);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, dst_ip, &sin.sin_addr);

    int total_len = sizeof(struct ip) + icmp_len;
    if (sendto(sd, buffer, total_len, 0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error");
        return 1;
    }

    printf("[+] 已发送伪造 ICMP 包: %s -> %s, 长度 %d 字节\n",
           src_ip, dst_ip, total_len);

    close(sd);
    return 0;

}
