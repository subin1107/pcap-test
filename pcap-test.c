#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <libnet.h> 

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

void print_Ethernet_Header(struct libnet_ethernet_hdr* eth_hdr) {
    printf("Ethernet Header\n");
    printf("Source MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x:", eth_hdr->ether_shost[i]);
    }
    printf("\n");
    printf("Destination MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x:", eth_hdr->ether_dhost[i]);
    }
    printf("\n");
}

void print_IP_Header(struct libnet_ipv4_hdr* ip_hdr) {
    printf("\nIP Header\n");
    u_int32_t src = ntohl(ip_hdr->ip_src.s_addr);
    u_int32_t dst = ntohl(ip_hdr->ip_dst.s_addr); 

    printf("Source IP: ");
    printf("%d.%d.%d.%d\n", src >> 24, (u_char)(src >> 16), (u_char)(src >> 8), (u_char)(src));
    printf("Destination IP: ");
    printf("%d.%d.%d.%d\n", dst >> 24, (u_char)(dst >> 16), (u_char)(dst >> 8), (u_char)(dst));
    printf("\n");
}

void print_TCP_Header(struct libnet_tcp_hdr* tcp_hdr) {
    printf("\nTCP Header\n");

    printf("Source port : %d\n", ntohs(tcp_hdr->th_sport));
    printf("Destination port : %d\n", ntohs(tcp_hdr->th_dport));
}

void print_Payload(const u_char* packet, u_int offset, u_int total_len) {
    printf("\nPayload Data: ");

    if (total_len <= offset) {
        printf("no DATA\n");
    } else {
        u_int cnt = total_len - offset;
        int len = cnt < 10 ? cnt : 10;
        for (uint8_t i = 0; i < len; i++) {
            printf("%02x ", *(packet + offset + i));
        }
    }
    printf("\n");
}

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + 14);
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + 14 + (ip_hdr->ip_hl) * 4);

        if (ntohs(eth_hdr->ether_type) != 0x0800) 
            continue;

        if (ip_hdr->ip_p != 0x6) 
            continue;

        print_Ethernet_Header(eth_hdr);
        print_IP_Header(ip_hdr);
        print_TCP_Header(tcp_hdr);
        uint32_t offset = 14 + (ip_hdr->ip_hl) * 4 + (tcp_hdr->th_off) * 4; // packet to data start offset
        print_Payload(packet, offset, header->caplen);
        printf("-------------------------------------------\n");
    }

    pcap_close(pcap);
    return 0;
}

