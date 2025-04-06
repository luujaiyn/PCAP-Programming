#ifndef MYHEADER_H
#define MYHEADER_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; 
    u_char  ether_shost[6];    
    u_short ether_type;      
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, 
                     iph_ver:4; 
  unsigned char      iph_tos; 
  unsigned short int iph_len; 
  unsigned short int iph_ident;
  unsigned short int iph_flag:3, 
                     iph_offset:13;
  unsigned char      iph_ttl; 
  unsigned char      iph_protocol;
  unsigned short int iph_chksum; 
  struct  in_addr    iph_sourceip;
  struct  in_addr    iph_destip; 
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;              
    u_short tcp_dport;              
    u_int   tcp_seq;                 
    u_int   tcp_ack;                  
    u_char  tcp_offx2;            
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;             
    u_short tcp_sum;                 
    u_short tcp_urp;               
};

// 이더넷 헤더 정보 출력 함수
void print_ethernet_header(const struct ethheader *eth_header) {
    printf("Ethernet Header:\n");
    printf("  Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1], 
           eth_header->ether_shost[2], eth_header->ether_shost[3], 
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("  Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], 
           eth_header->ether_dhost[2], eth_header->ether_dhost[3], 
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
}

// IP 헤더 정보 출력 함수
void print_ip_header(const struct ipheader *ip_header) {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    
    // IP 주소를 문자열로 변환
    inet_ntop(AF_INET, &(ip_header->iph_sourceip), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->iph_destip), dst_ip, INET_ADDRSTRLEN);
    
    printf("IP Header:\n");
    printf("  IP Version: %d\n", ip_header->iph_ver);
    printf("  IP Header Length: %d bytes\n", ip_header->iph_ihl * 4);
    printf("  Source IP: %s\n", src_ip);
    printf("  Destination IP: %s\n", dst_ip);
}

// TCP 헤더 정보 출력 함수
void print_tcp_header(const struct tcpheader *tcp_header) {
    printf("TCP Header:\n");
    printf("  Source Port: %d\n", ntohs(tcp_header->tcp_sport));
    printf("  Destination Port: %d\n", ntohs(tcp_header->tcp_dport));
    printf("  TCP Header Length: %d bytes\n", TH_OFF(tcp_header) * 4);
}

// 패킷 데이터 출력 함수
void print_packet_data(const unsigned char* data, int size) {
    if (size <= 0) {
        printf("  No Data Payload\n");
        return;
    }
    
    printf("Message Payload (%d bytes):\n", size);
    
    // 최대 64바이트까지만 출력
    int print_len = size > 64 ? 64 : size;
    
    // 16바이트씩 출력
    for (int i = 0; i < print_len; i++) {
        if (i % 16 == 0) printf("  ");
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (print_len % 16 != 0) printf("\n");
    
    // ASCII 형태로 출력
    printf("  ASCII: ");
    for (int i = 0; i < print_len; i++) {
        if (data[i] >= 32 && data[i] <= 126)
            printf("%c", data[i]);
        else
            printf(".");
    }
    printf("\n");
}

#endif // MYHEADER_H

