#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
// 每抓到数据包，pcap自动调用该回调函数
// 编译命令：g++ -o sniffer sniffer.c -lpcap
void print_hex(const u_char *data, size_t len){
    printf("0x00: ");
    for (size_t i = 0; i < len; i++){
        printf("%02x ", data[i]);
        if ((i+1) % 16 == 0)
            printf("\n0x%02lx: ", i+1);
    }
    printf("\n");
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    // 解析数据包以太网帧 + ip数据报
    const struct ether_header *eth = (const struct ether_header *)packet;
    const struct ip *ip_hdr = (const struct ip *)(packet + 14);

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip_hdr->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst, sizeof(dst));

    printf("Got a packet, the packet length is %u bytes\n", header->caplen);
    printf("[%s -> %s]\n", src, dst);
    print_hex(packet, header->caplen);
    printf("-------------\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    // 打开网卡会话，把eth3修改为自己的网卡（br‑xxxx）
    handle = pcap_open_live("br-24e94d95f9ab", BUFSIZ, 1, 1000, errbuf);

    // 编译BPF过滤表达式
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // 循环捕获数据包，‑1代表无限抓包
    pcap_loop(handle, -1, got_packet, NULL);
    
    pcap_close(handle);
    return 0;
}
