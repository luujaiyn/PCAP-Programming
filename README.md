# PCAP-Programming
C, C++ 기반 PCAP API를 활용하여 패킷의 정보를 출력하는 프로그램 작성하기
-------------------
PCAP(Packet Capyure)은 네트워크 트래픽 데이터를 캡쳐하고 저장하는 포멧이다.
PCAP API를 사용하여 네트워크 패킷을 캡쳐하고 분석하며 libcap을 이용해서 실시간 네트워크 트래픽을 캡쳐하고 캡쳐한 패킷의 정보를 출력하는  C 프로그램이다!

- myheaer.h 파일
  > 패킷 분석에 필요한 구조체들을 정의함
  > 패킷 정보를 출력하는 유틸리티 함수를 선언함
  > 상수 및 매크로를 정의함
- pcap_analyzer.c 파일
  > 프로그램의 메인 로직 구현
  > 패킷 캡쳐 초기화 및 설정(네트워크 인터페이스 열기, 필터 적용)
  > 패킷 처리 콜백 함수 구현
  > 캡쳐된 패킷에서 헤더 구조체 추출 및 분석
  > 프로그램 실행 흐름 제어
-----------
<실행 환경>
VMware 내의 우분투 이용
- 세팅 명령어
-  sudo apt update
-   sudo apt install libcap-dev

nano 를 통해 코드 작성

개발 환경 확인 & 준비
- 설치 명령어 (Ubuntu)
- sudo apt update
- sudo apt install libpcap-dev gcc

  -----------
  [컴파일]
  - gcc main.c -o sniffer -lpcap

[패킷 캡쳐 실행]
- sudo ./sniffer

[Firefox 열고 HTTP 접속하기]
- firefox http://example.com
-------------
<결과>
![image](https://github.com/user-attachments/assets/e60836e0-13a9-4875-995d-b7b905580c4a)

