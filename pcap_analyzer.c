#include "myheader.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 패킷 처리 콜백 함수
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth_header;
    struct ipheader *ip_header;
    struct tcpheader *tcp_header;
    
    int ethernet_header_length = 14; // 이더넷 헤더 크기는 14바이트
    
    // 패킷 길이 검사
    if (header->len < ethernet_header_length) {
        printf("패킷이 너무 짧습니다. 스킵합니다.\n");
        return;
    }
    
    // 이더넷 헤더 처리
    eth_header = (struct ethheader *)packet;
    printf("\n====== 새로운 패킷 캡처됨 ======\n");
    print_ethernet_header(eth_header);
    
    // IP 패킷인지 확인 (이더넷 타입 필드가 IP인지, 즉 0x0800인지 확인)
    if (ntohs(eth_header->ether_type) != 0x0800) {
        printf("IP 패킷이 아님. 스킵합니다.\n");
        return;
    }
    
    // IP 헤더 처리
    ip_header = (struct ipheader *)(packet + ethernet_header_length);
    int ip_header_length = ip_header->iph_ihl * 4; // IP 헤더 길이 (4바이트 단위)
    
    print_ip_header(ip_header);
    
    // TCP 패킷인지 확인 (IP 프로토콜 필드가 TCP인지, 즉 6인지 확인)
    if (ip_header->iph_protocol != 6) {
        printf("TCP 패킷이 아님. 스킵합니다.\n");
        return;
    }
    
    // TCP 헤더 처리
    tcp_header = (struct tcpheader *)(packet + ethernet_header_length + ip_header_length);
    int tcp_header_length = TH_OFF(tcp_header) * 4; // TCP 헤더 길이 (4바이트 단위)

    print_tcp_header(tcp_header);
    
    // 데이터 페이로드 처리
    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
    int payload_length = header->caplen - total_headers_size;
    
    if (payload_length > 0) {
        const u_char *payload = packet + total_headers_size;
        print_packet_data(payload, payload_length);
    } else {
        printf("  No Data Payload\n");
    }
    
    printf("===============================\n");
}

int main(int argc, char *argv[]) {
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    bpf_u_int32 mask;
    
    // 사용 가능한 모든 디바이스 목록 가져오기
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "디바이스를 찾을 수 없습니다: %s\n", errbuf);
        return 1;
    }
    
    // 첫 번째 디바이스 선택
    dev = alldevs;
    if (dev == NULL) {
        fprintf(stderr, "사용 가능한 디바이스가 없습니다.\n");
        return 1;
    }
    printf("선택된 디바이스: %s\n", dev->name);
    
    // 네트워크 주소와 마스크 얻기
    if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "디바이스 정보를 가져올 수 없습니다: %s\n", errbuf);
        net = 0;
        mask = 0;
    }
    
    // 패킷 캡처 핸들 열기
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "디바이스를 열 수 없습니다: %s\n", errbuf);
        return 2;
    }
    
    // 이더넷 디바이스인지 확인
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "이더넷 디바이스가 아닙니다\n");
        return 3;
    }
    
    // 필터 컴파일
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "필터를 컴파일할 수 없습니다: %s\n", pcap_geterr(handle));
        return 4;
    }
    
    // 필터 적용
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터를 적용할 수 없습니다: %s\n", pcap_geterr(handle));
        return 5;
    }
    
    // 패킷 캡처 시작 (무한 루프, Ctrl+C로 종료)
    printf("TCP 패킷 캡처 시작... (종료: Ctrl+C)\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // 정리
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    
    return 0;
}
