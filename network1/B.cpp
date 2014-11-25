#define  _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <tchar.h>
#include <WinSock2.h>
#include <Windows.h>

#include <stdlib.h>
#include <iostream>
#include <string>
#define HAVE_REMOTE

#include <pcap.h>
#include "tcp.h"
#pragma pack(1)  //��һ���ֽ��ڴ����
#define IPTOSBUFFERS    12
#define ETH_ARP         0x0806  //��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
#define ARP_HARDWARE    1  //Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ
#define ETH_IP          0x0800  //Э�������ֶα�ʾҪӳ���Э���ַ����ֵΪx0800��ʾIP��ַ
#define ARP_REQUEST     1
#define ARP_REPLY       2
#define HOSTNUM         255
void sendHello();
void receiveMessage();
unsigned char SendBuffer[200];
// ����ԭ��
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
int SendArp(pcap_t *adhandle, char *ip, unsigned char *mac);
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac);
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);
//14�ֽ���̫��֡�ṹ
struct ethernet_head {
	unsigned char dest_mac_add[6];    //Ŀ��mac��ַ
	unsigned char source_mac_add[6]; //Դmac��ַ
	unsigned short type;              //֡����
};
ethernet_head * rec_eth_head;

struct IpHeader {
	unsigned char Version_HLen;              //1byte �汾����
	unsigned char TOS;              //1byte ��������
	short Length;
	short Ident;
	short Flags_Offset;
	unsigned char TTL;
	unsigned char Protocol;
	short Checksum;
	unsigned int SourceAddr;
	unsigned int DestinationAddr;
};

struct TcpHeader {
	unsigned short SrcPort;	//2byte
	unsigned short DstPort;	//2byte
	unsigned int SequenceNum;			//4byte
	unsigned int Acknowledgment;	//4byte
	unsigned char HdrLen;			//1byte
	unsigned char Flags;			//1byte
	unsigned short AdvertisedWindow;		//2byte
	unsigned short Checksum;				//2byte
	unsigned short UrgPtr;						//2byte
};
//20byte

unsigned short checksum(unsigned short *data, int length) {
	unsigned long temp = 0;
	while (length > 1) {
		temp += *data++;
		length -= sizeof(unsigned short);
	}
	if (length) {
		temp += *(unsigned short*) data;
	}
	temp = (temp >> 16) + (temp & 0xffff);
	temp += (temp >> 16);
	return (unsigned short) (~temp);
}
//28�ֽ�ARP֡�ṹ
struct arp_head {
	unsigned short hardware_type;    //Ӳ������
	unsigned short protocol_type;    //Э������
	unsigned char hardware_add_len; //Ӳ����ַ����
	unsigned char protocol_add_len; //Э���ַ����
	unsigned short operation_field; //�����ֶ�
	unsigned char source_mac_add[6]; //Դmac��ַ
	unsigned long source_ip_add;    //Դip��ַ
	unsigned char dest_mac_add[6]; //Ŀ��mac��ַ
	unsigned long dest_ip_add;      //Ŀ��ip��ַ
};
//arp���հ��ṹ
struct arp_packet {
	struct ethernet_head ed;
	struct arp_head ah;
};
struct PsdTcpHeader {
	unsigned long SourceAddr;
	unsigned long DestinationAddr;
	char Zero;
	char Protcol;
	unsigned short TcpLen;
};

char TcpData[] = "Hello";
struct sparam {
	pcap_t *adhandle;
	char *ip;
	unsigned char *mac;
	char *netmask;
};
struct gparam {
	pcap_t *adhandle;
};
bool flag;
struct sparam sp;
struct gparam gp;
struct ethernet_head ethernet;
struct IpHeader ip;
struct TcpHeader tcp;
struct PsdTcpHeader ptcp;
HANDLE sendthread;
HANDLE recvthread;
/**��¼ɨ�赽��MAC��IP��Ӧ����Ϣ*/
struct MacMapIP {
	unsigned char Mac[6];
	unsigned long IP[4];
} Machines[256];
int countMachine = 0;
//����ʱ�������޸�
char * sourIP;
char * destIP;
/**����¼�Ƿ����Ѿ�ɨ�������*/
boolean scanFinished = false;
/**���������MAC*/
unsigned char selfMAC[6];
int Result;
pcap_t *adhandle, *adhandle2;

char *ip_addr;
char *ip_netmask;
unsigned char *ip_mac;
pcap_if_t *alldevs;
pcap_if_t *d;
int inum;
int cMacIP;

int i = 0;
char errbuf[PCAP_ERRBUF_SIZE];
u_int netmask;
char packet_filter[] = "tcp and(ether dst 74-E5-0B-F4-BD-07)"; //�Լ�����ip��ַ����
struct bpf_program fcode;
int main() {
	/* ��ȡ�����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
	for (d = alldevs; d; d = d->next) {
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת��ѡ�е������� */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* ���豸 */
	if ((adhandle = pcap_open(d->name, // �豸��
			65535, // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
			PCAP_OPENFLAG_PROMISCUOUS, // ����ģʽ
			1000, // ��ȡ��ʱʱ��
			NULL, // Զ�̻�����֤
			errbuf // ���󻺳��
			)) == NULL) {
		fprintf(stderr,
				"\nUnable to open the adapter. %s is not supported by WinPcap\n",
				d->name);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...n", d->description);

	/* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("datalink:[%d]\n", pcap_datalink(adhandle));

	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask =
				((struct sockaddr_in *) (d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;

	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		fprintf(stderr,
				"\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		int x;
		scanf("%d", &x);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...\n", d->description);

	receiveMessage();


	/**�����ǽ�����Ϣ�Ĺ���*/

	pcap_freealldevs(alldevs);

//liebao
	inum = 4;
	/* ��ȡ�����豸�б� */
		if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
			fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}

	/* ��ת��ѡ�е������� */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
		;
	ip_addr = (char *) malloc(sizeof(char) * 16); //�����ڴ���IP��ַ
	if (ip_addr == NULL) {
		printf("�����ڴ���IP��ַʧ��!\n");
		return -1;
	}
	ip_netmask = (char *) malloc(sizeof(char) * 16); //�����ڴ���NETMASK��ַ
	if (ip_netmask == NULL) {
		printf("�����ڴ���NETMASK��ַʧ��!\n");
		return -1;
	}
	ip_mac = (unsigned char *) malloc(sizeof(unsigned char) * 6); //�����ڴ���MAC��ַ
	if (ip_mac == NULL) {
		printf("�����ڴ���MAC��ַʧ��!\n");
		return -1;
	}

	/* ���豸 */
	if ((adhandle2 = pcap_open(d->name, // �豸��
			65535, // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
			PCAP_OPENFLAG_PROMISCUOUS, // ����ģʽ
			1000, // ��ȡ��ʱʱ��
			NULL, // Զ�̻�����֤
			errbuf // ���󻺳��
			)) == NULL) {
		fprintf(stderr,
				"\nUnable to open the adapter. %s is not supported by WinPcap\n",
				d->name);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...n", d->description);
	ifget(d, ip_addr, ip_netmask);            //��ȡ��ѡ�����Ļ�����Ϣ--����--IP��ַ
	GetSelfMac(adhandle2, ip_addr, ip_mac);         //���������豸��������豸ip��ַ��ȡ���豸��MAC��ַ
	sp.adhandle = adhandle2;
	sp.ip = ip_addr;
	sp.mac = ip_mac;
	sp.netmask = ip_netmask;
	gp.adhandle = adhandle2;
	sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) SendArpPacket,
			&sp, 0, NULL);
	recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) GetLivePC, &gp,
			0, NULL);
	while (!scanFinished) {
		Sleep(1000);
	}

	for(int j=0;j<countMachine;j++){
		if(Machines[j].IP[0]==192&&Machines[j].IP[1]==168&&Machines[j].IP[2]==191&&Machines[j].IP[3]==191){
			cMacIP=j;break;
		}
	}

	printf("\n--------Going to router--------\n");


	sendHello();

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	return 0;
}

void receiveMessage() {
	/* ��ʼ���� */
	int ret;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	boolean getit = false;
	while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0 && (!getit)) {
		if (ret == 0) {
			/* ��ʱʱ�䵽 */
			printf("time over!\n");
			continue;
		}
		char buffer[100];
		if (header->len > 0) {
			printf("len:[%d]n", header->len);
			//��ȡmac
			rec_eth_head = (ethernet_head*) pkt_data;
			for (int j = 0; j < 6; j++) {
				char * temp = (char*) malloc(sizeof(char));
				_itoa((int) (rec_eth_head->dest_mac_add[j]), temp, 16);
				printf("%s  ", temp);
			}
			printf("DestMac:\n");

			//��ȡ���е�ip
			ip_header *ip = (ip_header *) (pkt_data + 14);
			printf("daddr:[%u.%u.%u.%u]n", ip->daddr.byte1, ip->daddr.byte2,
					ip->daddr.byte3, ip->daddr.byte4);
			//			sourIP=(char *)malloc(sizeof(char*));
			//			strcat(sourIP,ip->daddr.byte1+".");
			//			strcat(sourIP,ip->daddr.byte2+".");
			//			strcat(sourIP,ip->daddr.byte3+".");
			//			strcat(sourIP,ip->daddr.byte4+"");
			//			printf("sourip%s", sourIP);
			printf("saddr:[%u.%u.%u.%u]n", ip->saddr.byte1, ip->saddr.byte2,
					ip->saddr.byte3, ip->saddr.byte4);
			//			destIP=(char *)malloc(sizeof(char*));
			//			strcat(destIP,ip->daddr.byte1+".");
			//			strcat(destIP,ip->daddr.byte2+".");
			//			strcat(destIP,ip->daddr.byte3+".");
			//			strcat(destIP,ip->daddr.byte4+"");

			if (!(ip->daddr.byte1 == 192 && ip->daddr.byte2 == 168
					&& ip->daddr.byte3 == 191 && ip->daddr.byte4 == 1))
				continue;

			tcp_header *tcp = (tcp_header *) ((u_char*) ip
					+ (ip->ver_ihl & 0xf) * 4);

			char *data = (char*) ((char *) tcp + (tcp->hlen) * 4);
			u_int datalen = ntohs(ip->tlen) - (ip->ver_ihl & 0xf) * 4
					- (tcp->hlen) * 4;
			printf("ipheader�ĳ���%d\ntcpͷ�ĳ���%d\n���ݳ���%d\n",
					(ip->ver_ihl & 0xf) * 4, (tcp->hlen) * 4, datalen);
			memcpy(buffer, data, datalen);
			memcpy(TcpData, data, datalen);
			printf("buffer:[%s]n", buffer);
			getit = true;

		}
	}

}
void sendHello() {
	memset(&ethernet, 0, sizeof(ethernet));
//	memcpy(ethernet.dest_mac_add, rec_eth_head->source_mac_add, 6);
	BYTE destmac[8];
	destmac[0] = 0x74;
	destmac[1] = 0xe5;
	destmac[2] = 0x0b;
	destmac[3] = 0xf4;
	destmac[4] = 0xbd;
	destmac[5] = 0x07;
	memcpy(ethernet.dest_mac_add, destmac, 6);
	memcpy(ethernet.source_mac_add, selfMAC, 6);
	ethernet.type = htons(0x0800);
	memcpy(&SendBuffer, &ethernet, sizeof(struct ethernet_head));
	ip.Version_HLen = 0x45;
	ip.TOS = 0;
	ip.Length = htons(
			sizeof(struct IpHeader) + sizeof(struct TcpHeader)
					+ strlen(TcpData));
	ip.Ident = htons(1);
	ip.Flags_Offset = 0;
	ip.TTL = 128;
	ip.Protocol = 6;
	ip.Checksum = 0;
	ip.SourceAddr = inet_addr("192.168.1.103");
	ip.DestinationAddr = inet_addr("192.168.191.1");
//	ip.SourceAddr = inet_addr(sourIP);
//	ip.DestinationAddr = inet_addr(destIP);
	memcpy(&SendBuffer[sizeof(struct ethernet_head)], &ip, 20);
	tcp.DstPort = htons(88);
	tcp.SrcPort = htons(1000);
	tcp.SequenceNum = htonl(11);
	tcp.Acknowledgment = 0;
	tcp.HdrLen = 0x50;
	tcp.Flags = 0x18;
	tcp.AdvertisedWindow = htons(512);
	tcp.UrgPtr = 0;
	tcp.Checksum = 0;
	memcpy(&SendBuffer[sizeof(struct ethernet_head) + 20], &tcp, 20);
	ptcp.SourceAddr = ip.SourceAddr;
	ptcp.DestinationAddr = ip.DestinationAddr;
	ptcp.Zero = 0;
	ptcp.Protcol = 6;
	ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(TcpData));

	char TempBuffer[65535];
	memcpy(TempBuffer, &ptcp, sizeof(struct PsdTcpHeader));
	memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &tcp,
			sizeof(struct TcpHeader));
	memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader),
			TcpData, strlen(TcpData));
	tcp.Checksum = checksum((USHORT*) (TempBuffer),
			sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader)
					+ strlen(TcpData));

	memcpy(SendBuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader),
			&tcp, sizeof(struct TcpHeader));
	memcpy(
			SendBuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader)
					+ sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	memset(TempBuffer, 0, sizeof(TempBuffer));
	memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
	ip.Checksum = checksum((USHORT*) (TempBuffer), sizeof(struct IpHeader));
	memcpy(SendBuffer + sizeof(struct ethernet_head), &ip,
			sizeof(struct IpHeader));
	Result = pcap_sendpacket(adhandle2, SendBuffer,
			sizeof(struct ethernet_head) + sizeof(struct IpHeader)
					+ sizeof(struct TcpHeader) + strlen(TcpData));
	printf("The length is %d\n",
			sizeof(struct ethernet_head) + sizeof(struct IpHeader)
					+ sizeof(struct TcpHeader) + strlen(TcpData));
	if (Result != 0) {
		printf("Send Error!\n");
	} else {
		printf("Send TCP Packet.\n");
		printf("Dstination Port:%d\n", ntohs(tcp.DstPort));
		printf("Source Port:%d\n", ntohs(tcp.SrcPort));
		printf("Sequence:%d\n", ntohl(tcp.SequenceNum));
		printf("Acknowledgment:%d\n", ntohl(tcp.Acknowledgment));
		printf("Header Length:%d*4\n", tcp.HdrLen >> 4);
		printf("Flags:0x%0x\n", tcp.Flags);
		printf("AdvertiseWindow:%d\n", ntohs(tcp.AdvertisedWindow));
		printf("UrgPtr:%d\n", ntohs(tcp.UrgPtr));
		printf("Checksum:%u\n", ntohs(tcp.Checksum));
	}

	printf("\n\n************************\nSend to C message successfully!");
	getchar();
	getchar();
}
/* ��ȡ������Ϣ*/
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask) {
	pcap_addr_t *a;
	char ip6str[128];
	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		switch (a->addr->sa_family) {
		case AF_INET:
			if (a->addr) {
				char *ipstr;
				ipstr = iptos(
						((struct sockaddr_in *) a->addr)->sin_addr.s_addr); //*ip_addr
				memcpy(ip_addr, ipstr, 16);
			}
			if (a->netmask) {
				char *netmaskstr;
				netmaskstr = iptos(
						((struct sockaddr_in *) a->netmask)->sin_addr.s_addr);

				memcpy(ip_netmask, netmaskstr, 16);
			}
		case AF_INET6:
			break;
		}
	}
}

/* ������������п��ܵ�IP��ַ����ARP������߳� */
DWORD WINAPI SendArpPacket(LPVOID lpParameter) //(pcap_t *adhandle,char *ip,unsigned char *mac,char *netmask)
		{
	sparam *spara = (sparam *) lpParameter;
	pcap_t *adhandle = spara->adhandle;
	char *ip = spara->ip;
	unsigned char *mac = spara->mac;
	char *netmask = spara->netmask;
	printf("ip_mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
	printf("�����IP��ַΪ:%s\n", ip);
	printf("��ַ����NETMASKΪ:%s\n", netmask);
	printf("\n");
	unsigned char sendbuf[42]; //arp���ṹ��С
	struct ethernet_head eh;
	struct arp_head ah;
	memset(eh.dest_mac_add, 0xff, 6); //Ŀ�ĵ�ַΪȫΪ�㲥��ַ
	memcpy(eh.source_mac_add, mac, 6);
	memcpy(ah.source_mac_add, mac, 6);
	memset(ah.dest_mac_add, 0x00, 6);
	eh.type = htons(ETH_ARP);
	ah.hardware_type = htons(ARP_HARDWARE);
	ah.protocol_type = htons(ETH_IP);
	ah.hardware_add_len = 6;
	ah.protocol_add_len = 4;
	ah.source_ip_add = inet_addr(ip); //���󷽵�IP��ַΪ�����IP��ַ
	ah.operation_field = htons(ARP_REQUEST);
	//��������ڹ㲥����arp��
	unsigned long myip = inet_addr(ip);
	unsigned long mynetmask = inet_addr(netmask);
	unsigned long hisip = htonl((myip & mynetmask));
	for (int i = 0; i < HOSTNUM; i++) {
		ah.dest_ip_add = htonl(hisip + i);
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &eh, sizeof(eh));
		memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
		if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
			//printf("\nPacketSend succeed\n");
		} else {
			printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		}
		Sleep(50);
	}
	Sleep(1000);
	flag = TRUE;
	return 0;
}
/* �������������ݰ���ȡ�������IP��ַ */
DWORD WINAPI GetLivePC(LPVOID lpParameter) //(pcap_t *adhandle)
		{
	gparam *gpara = (gparam *) lpParameter;
	pcap_t *adhandle = gpara->adhandle;
	int res;
	unsigned char Mac[6];
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;

	while (true) {
		if (flag) {
			printf("ɨ����ϣ���������˳�!\n");
			scanFinished = true;
			break;
		}
		if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
			if (*(unsigned short *) (pkt_data + 12) == htons(ETH_ARP)) {
				struct arp_packet *recv = (arp_packet *) pkt_data;
				if (*(unsigned short *) (pkt_data + 20) == htons(ARP_REPLY)) {
					printf("-------------------------------------------\n");
					Machines[countMachine].IP[0] = recv->ah.source_ip_add & 255;
					Machines[countMachine].IP[1] = recv->ah.source_ip_add >> 8
							& 255;
					Machines[countMachine].IP[2] = recv->ah.source_ip_add >> 16
							& 255;
					Machines[countMachine].IP[3] = recv->ah.source_ip_add >> 24
							& 255;
					printf("��ţ�%d	IP��ַ:%d.%d.%d.%d   MAC��ַ:", countMachine,
							recv->ah.source_ip_add & 255,
							recv->ah.source_ip_add >> 8 & 255,
							recv->ah.source_ip_add >> 16 & 255,
							recv->ah.source_ip_add >> 24 & 255);
					for (int i = 0; i < 6; i++) {
						Mac[i] = *(unsigned char *) (pkt_data + 22 + i);
						Machines[countMachine].Mac[i] = Mac[i];
//					printf("%u",Machines[countMachine].Mac[i]);
						printf("%02x", Mac[i]);
					}
					countMachine++;
					printf("\n");
				}
			}

		}

		Sleep(10);
	}
	scanFinished=true;


	return 0;
}
/* ��ȡ�Լ�������MAC��ַ
 �㲥һ��arp����������յ��İ���Դip���Լ��趨���Ǹ��� ��ô�����Լ��İ�����ô���������������ҵ��Լ���mac

 */
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac) {
	unsigned char sendbuf[42];            //arp���ṹ��С
	int i = -1;
	int res;
	struct ethernet_head eh;
	struct arp_head ah;
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	memset(eh.dest_mac_add, 0xff, 6);            //Ŀ�ĵ�ַΪȫΪ�㲥��ַ
	memset(eh.source_mac_add, 0x0f, 6);
	memset(ah.source_mac_add, 0x0f, 6);
	memset(ah.dest_mac_add, 0x00, 6);
	eh.type = htons(ETH_ARP);
	ah.hardware_type = htons(ARP_HARDWARE);
	ah.protocol_type = htons(ETH_IP);
	ah.hardware_add_len = 6;
	ah.protocol_add_len = 4;
	ah.source_ip_add = inet_addr("100.100.100.100"); //����������ip
	ah.operation_field = htons(ARP_REQUEST);
	ah.dest_ip_add = inet_addr(ip_addr);

	memset(sendbuf, 0, sizeof(sendbuf));
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
		printf("\nPacketSend succeed\n");
	} else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		return 0;
	}
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		if (*(unsigned short *) (pkt_data + 12) == htons(ETH_ARP)
				&& *(unsigned short*) (pkt_data + 20) == htons(ARP_REPLY)
				&& *(unsigned long*) (pkt_data + 38)
						== inet_addr("100.100.100.100")) {
			for (i = 0; i < 6; i++) {
				ip_mac[i] = *(unsigned char *) (pkt_data + 22 + i);
				selfMAC[i] = ip_mac[i];
			}
			printf("��ȡ�Լ�������MAC��ַ�ɹ�!\n");
			break;
		}
	}
	if (i == 6) {
		return 1;
	} else {
		return 0;
	}
}

/* ���������͵�IP��ַת�����ַ������͵�*/
char *iptos(u_long in) {
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;
	p = (u_char *) &in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen) {
	socklen_t sockaddrlen;
#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif

	if (getnameinfo(sockaddr, sockaddrlen, address, addrlen,
	NULL, 0, NI_NUMERICHOST) != 0)
		address = NULL;
	return address;
}
