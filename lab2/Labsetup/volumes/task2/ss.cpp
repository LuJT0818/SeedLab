#include <pcap.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

using namespace std;
// 编译命令：g++ -o ss ss.cpp -lpcap

// 网桥接口名，根据实验环境实际修改
// 查看命令：ip link show | grep br-
#define IFACE "br-a91f707f420b"

/**
 * 计算校验和（Internet Checksum）
 * @param buf 数据缓冲区首地址
 * @param len 数据长度（字节）
 * @return 16位校验和（网络字节序）
 *
 * 算法：将数据按16位累加，溢出位回卷，最后取反。
 * IP头和ICMP头都使用此函数计算校验和。
 */
unsigned short checksum(void *buf, int len) {
    unsigned short *ptr = (unsigned short *)buf;
    unsigned int sum = 0;
    unsigned short result;

    // 按16位累加
    for (sum = 0; len > 1; len -= 2)
        sum += *ptr++;

    // 处理剩余单字节
    if (len == 1)
        sum += *(unsigned char *)ptr;

    // 溢出回卷
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;   // 取反
    return result;
}

/**
 * 构造ICMP回显应答头部
 * @param icmp_hdr 待填充的ICMP头（新缓冲区）
 * @param orig     原始ICMP请求头，用于复制id和seq
 *
 * 将类型设为ICMP_ECHOREPLY(0)，代码0，并复制原请求的id和seq，
 * 这样ping程序才能将回复与请求匹配。
 */
void make_icmp_header(struct icmp *icmp_hdr, const struct icmp *orig) {
    icmp_hdr->icmp_type  = ICMP_ECHOREPLY;  // 类型：回显应答
    icmp_hdr->icmp_code  = 0;               // 代码：0
    icmp_hdr->icmp_id    = orig->icmp_id;   // 复制请求的标识符
    icmp_hdr->icmp_seq   = orig->icmp_seq;  // 复制请求的序列号
    icmp_hdr->icmp_cksum = 0;               // 校验和先置0，稍后计算
}

/**
 * 构造IP头部
 * @param ip_hdr   待填充的IP头（新缓冲区）
 * @param src_ip   源IP字符串（点分十进制）
 * @param dst_ip   目的IP字符串
 * @param icmp_len ICMP部分的总长度（头+载荷）
 *
 * 设置IPv4、头长5（20字节）、总长度、TTL、协议等字段，
 * 并用传入的源/目的IP填充，最后计算IP头校验和。
 */
void make_ip_header(struct ip *ip_hdr, const char *src_ip, const char *dst_ip, int icmp_len) {
    ip_hdr->ip_v   = 4;                             // IPv4
    ip_hdr->ip_hl  = 5;                             // 头长 5*4=20 字节
    ip_hdr->ip_tos = 0;                             // 服务类型
    ip_hdr->ip_len = htons(sizeof(struct ip) + icmp_len); // 总长度（IP头+ICMP）
    ip_hdr->ip_id  = htons(rand() & 0xFFFF);        // 随机ID
    ip_hdr->ip_off = 0;                             // 分片偏移
    ip_hdr->ip_ttl = 64;                            // 生存时间
    ip_hdr->ip_p   = IPPROTO_ICMP;                  // 协议：ICMP
    ip_hdr->ip_sum = 0;                             // 校验和先置0
    inet_pton(AF_INET, src_ip, &ip_hdr->ip_src);    // 源IP
    inet_pton(AF_INET, dst_ip, &ip_hdr->ip_dst);    // 目的IP
    ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip)); // 计算IP头校验和
}

/**
 * pcap抓包回调函数
 * @param args   用户参数（此处未使用）
 * @param header pcap包头，包含时间戳和caplen（实际抓到的长度）
 * @param packet 指向原始数据帧的指针
 *
 * 功能：解析以太网→IP→ICMP，只处理ICMP Echo Request（type=8），
 *       立即构造对应的ICMP Echo Reply，源/目的IP交换后通过原始套接字发出。
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int caplen = header->caplen;        // 实际抓到的字节数
    const int eth_len = 14;             // 以太网头长度

    // 边界检查：至少要有以太网头+最小IP头
    if (caplen < eth_len + 20) return;

    // 解析以太网头，只处理IPv4
    const struct ether_header *eth = (const struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    // 解析IP头
    const struct ip *ip_hdr = (const struct ip *)(packet + eth_len);
    int ip_len = ip_hdr->ip_hl * 4;     // IP头实际长度
    if (ip_len < 20) return;            // 非法头长
    if (caplen < eth_len + ip_len + 8) return; // 至少要能容纳ICMP头
    if (ip_hdr->ip_p != IPPROTO_ICMP) return;  // 只处理ICMP

    // 解析ICMP头，只处理Echo Request（type=8）
    const struct icmp *icmp_hdr = (const struct icmp *)(packet + eth_len + ip_len);
    if (icmp_hdr->icmp_type != ICMP_ECHO) return;

    int icmp_offset = eth_len + ip_len; // ICMP起始偏移
    int icmp_len = caplen - icmp_offset; // ICMP总长度
    int payload_len = icmp_len - 8;      // 载荷长度（去掉ICMP头8字节）
    if (payload_len < 0) payload_len = 0;
    if (payload_len > 1000) payload_len = 1000; // 防止缓冲区溢出

    // 将原始IP地址转为字符串，便于日志输出
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_hdr->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst, sizeof(dst));

    // 准备发送缓冲区（存放完整的IP包）
    char buffer[1500];
    memset(buffer, 0, sizeof(buffer));
    struct ip *r_ip_hdr = (struct ip *)buffer;                           // 新IP头
    struct icmp *r_icmp_hdr = (struct icmp *)(buffer + sizeof(struct ip)); // 新ICMP头

    // 构造ICMP回复头（复制id/seq）
    make_icmp_header(r_icmp_hdr, icmp_hdr);

    // 复制原始ICMP载荷（ICMP头之后的8字节开始）
    if (payload_len > 0) {
        memcpy(buffer + sizeof(struct ip) + 8,
               packet + icmp_offset + 8, payload_len);
    }
    int total_icmp_len = 8 + payload_len; // ICMP总长度
    // 计算ICMP校验和
    r_icmp_hdr->icmp_cksum = checksum(r_icmp_hdr, total_icmp_len);

    // 构造IP头：源=原目的，目的=原源
    make_ip_header(r_ip_hdr, dst, src, total_icmp_len);

    // 创建原始套接字，用于发送自定义IP包
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket() error");
        exit(-1);
    }

    // 告诉内核：IP头由我们自己填充，不要额外添加
    int one = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt() error");
        close(sd);
        return;
    }

    // 设置目标地址为原始请求的源地址（即把回复发回给请求方）
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr = ip_hdr->ip_src;

    // 发送伪造的ICMP回复
    int total_len = sizeof(struct ip) + total_icmp_len;
    if (sendto(sd, buffer, total_len, 0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error");
    } else {
        cout << "[+] 嗅到 " << src << " -> " << dst
             << "，已伪造回复" << endl;
    }

    close(sd);
}

int main() {
    pcap_t *handle;                     // pcap会话句柄
    char errbuf[PCAP_ERRBUF_SIZE];      // 错误信息缓冲区
    struct bpf_program fp;              // 编译后的过滤器
    const char *filter_exp = "icmp and icmp[icmptype] == 8"; // 只抓ICMP Echo Request

    // 打开网卡会话：混杂模式=1，超时1000ms
    handle = pcap_open_live(IFACE, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "pcap_open_live(" IFACE "): " << errbuf << endl;
        return 1;
    }

    // 编译BPF过滤表达式
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "pcap_compile: " << pcap_geterr(handle) << endl;
        return 1;
    }
    // 应用过滤器
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    cout << "[*] 嗅探 " << IFACE << " 上的 ICMP Echo Request..." << endl;

    // 进入无限抓包循环，每抓到一个包调用 got_packet
    pcap_loop(handle, -1, got_packet, NULL);

    // 关闭会话
    pcap_close(handle);
    return 0;
}