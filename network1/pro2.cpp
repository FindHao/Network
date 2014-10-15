#define  _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include "pcap.h"
#include "Packet32.h"
#include "tcp.h"


#pragma pack(1)  //��һ���ֽ��ڴ����
#define IPTOSBUFFERS    12
#define ETH_ARP         0x0806  //��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
#define ARP_HARDWARE    1  //Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ
#define ETH_IP          0x0800  //Э�������ֶα�ʾҪӳ���Э���ַ����ֵΪx0800��ʾIP��ַ
#define ARP_REQUEST     1
#define ARP_REPLY       2
#define HOSTNUM         255
/* packet handler ����ԭ��*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
// ����ԭ��
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
int SendArp(pcap_t *adhandle, char *ip, unsigned char *mac);
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac);
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);

//28�ֽ�ARP֡�ṹ
struct arp_head
{
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

//14�ֽ���̫��֡�ṹ
struct ethernet_head
{
	unsigned char dest_mac_add[6];    //Ŀ��mac��ַ
	unsigned char source_mac_add[6]; //Դmac��ַ
	unsigned short type;              //֡����
};
//arp���հ��ṹ
struct arp_packet
{
	struct ethernet_head ed;
	struct arp_head ah;
};

////IP����ͷ  
//struct ip_header  //С��ģʽ  
//{
//	unsigned   char     ihl : 4;              //ip   header   length      
//	unsigned   char     version : 4;          //version     
//	u_char              tos;                //type   of   service     
//	u_short             tot_len;            //total   length     
//	u_short             id;                 //identification     
//	u_short             frag_off;           //fragment   offset     
//	u_char              ttl;                //time   to   live     
//	u_char              protocol;           //protocol   type     
//	u_short             check;              //check   sum     
//	u_int               saddr;              //source   address     
//	u_int               daddr;              //destination   address     
//};

//tcp����ͷ  
struct tcp_header2 //С��ģʽ  
{
	u_short   source;
	u_short   dest;
	u_int32_t   seq;
	u_int32_t   ack_seq;
	u_char lenres;
	u_char flag;
	u_short   window;
	u_short   check;
	u_short   urg_ptr;
};

//tcp��udp����У����ǵ�αͷ  
struct psd_header {
	u_int32_t   sourceip;       //ԴIP��ַ  
	u_int32_t   destip;         //Ŀ��IP��ַ  
	u_char      mbz;            //�ÿ�(0)  
	u_char      ptcl;           //Э������  
	u_int16_t   plen;           //TCP/UDP���ݰ��ĳ���(����TCP/UDP��ͷ�������ݰ������ĳ��� ��λ:�ֽ�)  
};

/**��̫������ͷ |  IP����ͷ | TCP����ͷ | ����*/
struct ethernet_packet{
	struct ethernet_head eh;
	struct ip_header iph;
	struct tcp_header2 tcph;
};


struct sparam
{
	pcap_t *adhandle;
	char *ip;
	unsigned char *mac;
	char *netmask;
};
struct gparam
{
	pcap_t *adhandle;
};
bool flag;
struct sparam sp;
struct gparam gp;


struct EthernetHeader
{
	u_char DestMAC[6];
	u_char SourMAC[6];
	u_short EthType;
};
struct IpHeader
{
	unsigned char Version_HLen;
	unsigned char TOS;
	short Length;
	short Ident;
	short Flags_Offset;
	unsigned char TTL;
	unsigned char Protocol;
	short Checksum;
	unsigned int SourceAddr;
	unsigned int DestinationAddr;
};
struct PsdTcpHeader
{
	unsigned long SourceAddr;
	unsigned long DestinationAddr;
	char Zero;
	char Protcol;
	unsigned short TcpLen;
};
struct TcpHeader
{
	unsigned short SrcPort;
	unsigned short DstPort;
	unsigned int SequenceNum;
	unsigned int Acknowledgment;
	unsigned char HdrLen;
	unsigned char Flags;
	unsigned short AdvertisedWindow;
	unsigned short Checksum;
	unsigned short UrgPtr;
};
unsigned short checksum(unsigned short *data, int length)
{
	unsigned long temp = 0;
	while (length > 1)
	{
		temp += *data++;
		length -= sizeof(unsigned short);
	}
	if (length)
	{
		temp += *(unsigned short*)data;
	}
	temp = (temp >> 16) + (temp & 0xffff);
	temp += (temp >> 16);
	return (unsigned short)(~temp);
}


int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *ip_addr;
	char *ip_netmask;
	unsigned char *ip_mac;
	HANDLE sendthread;
	HANDLE recvthread;

	ip_addr = (char *)malloc(sizeof(char) * 16);//�����ڴ���IP��ַ
	if (ip_addr == NULL)
	{
		printf("�����ڴ���IP��ַʧ��!\n");
		return -1;
	}
	ip_netmask = (char *)malloc(sizeof(char) * 16);//�����ڴ���NETMASK��ַ
	if (ip_netmask == NULL)
	{
		printf("�����ڴ���NETMASK��ַʧ��!\n");
		return -1;
	}
	ip_mac = (unsigned char *)malloc(sizeof(unsigned char) * 6);//�����ڴ���MAC��ַ
	if (ip_mac == NULL)
	{
		printf("�����ڴ���MAC��ַʧ��!\n");
		return -1;
	}
	/* ��ȡ�����豸�б�*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* ��ӡ�б�*/
	printf("[���������б�]\n");
	for (d = alldevs; d; d = d->next)
	{
		printf("%d) %s\n", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0)
	{
		printf("\n�Ҳ�����������ȷ���Ƿ��Ѱ�װWinPcap.\n");
		return -1;
	}
	printf("\n");
	printf("��ѡ��Ҫ�򿪵�������(1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\n�������ų�������������!�밴������˳���\n");
		getchar();
		getchar();
		/* �ͷ��豸�б�*/
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* ��ת��ѡ�е�������*/
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);
	/* ���豸*/
	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
		)) == NULL)
	{
		fprintf(stderr, "\n�޷���ȡ��������. ������%s ����WinPcap֧��\n", d->name);
		/* �ͷ��豸�б�*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on ����%d ...\n", inum);








	u_int netmask;
	char packet_filter[] = "tcp and (src host *.*.*.*)";//�Լ�����ip��ַ����
	struct bpf_program fcode;


	/* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "nThis program works only on Ethernet networks.n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("datalink:[%d]n", pcap_datalink(adhandle));
	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;


	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "nUnable to compile the packet filter. Check the syntax.n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		int x;
		scanf("%d", &x);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "nError setting the filter.n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);



	/* ��ʼ���� */
	int ret;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;


	while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (ret == 0)
		{
			/* ��ʱʱ�䵽 */
			printf("time over!n");
			continue;
		}
		char buffer[20000];
		if (header->len > 0)
		{
			printf("len:[%d]n", header->len);
			ip_header *ip = (ip_header *)(pkt_data + 14);
			printf("daddr:[%u.%u.%u.%u]n", ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);
			printf("saddr:[%u.%u.%u.%u]n", ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4);
			tcp_header *tcp = (tcp_header *)((u_char*)ip + (ip->ver_ihl & 0xf) * 4);
			char *data = (char *)tcp + (tcp->hlen) * 4;
			u_int datalen = ntohs(ip->tlen) - (ip->ver_ihl & 0xf) * 4 - (tcp->hlen) * 4;


			memcpy(buffer, data, datalen);
			buffer[datalen] =' ';
			printf("buffer:[%s]n", buffer + 20);
		}
	}
	return 0;
}
/* ��ȡ������Ϣ*/
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask)
{
	pcap_addr_t *a;
	char ip6str[128];
	/* IP addresses */
	for (a = d->addresses; a; a = a->next)
	{
		switch (a->addr->sa_family)
		{
		case AF_INET:
			if (a->addr)
			{
				char *ipstr;
				ipstr = iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);//*ip_addr
				memcpy(ip_addr, ipstr, 16);
			}
			if (a->netmask)
			{
				char *netmaskstr;
				netmaskstr = iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);

				memcpy(ip_netmask, netmaskstr, 16);
			}
		case AF_INET6:
			break;
		}
	}
}

/* ���������͵�IP��ַת�����ַ������͵�*/
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;
	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;
#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif

	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;
	return address;
}
/* ��ȡ�Լ�������MAC��ַ
�㲥һ��arp����������յ��İ���Դip���Լ��趨���Ǹ��� ��ô�����Լ��İ�����ô���������������ҵ��Լ���mac

*/
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac)
{
	unsigned char sendbuf[42];//arp���ṹ��С
	int i = -1;
	int res;
	struct ethernet_head eh;
	struct arp_head ah;
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	memset(eh.dest_mac_add, 0xff, 6);//Ŀ�ĵ�ַΪȫΪ�㲥��ַ
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
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0)
	{
		printf("\nPacketSend succeed\n");
	}
	else
	{
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		return 0;
	}
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)
	{
		if (*(unsigned short *)(pkt_data + 12) == htons(ETH_ARP) &&
			*(unsigned short*)(pkt_data + 20) == htons(ARP_REPLY) &&
			*(unsigned long*)(pkt_data + 38) == inet_addr("100.100.100.100"))
		{
			for (i = 0; i<6; i++)
			{
				ip_mac[i] = *(unsigned char *)(pkt_data + 22 + i);
			}
			printf("��ȡ�Լ�������MAC��ַ�ɹ�!\n");
			break;
		}
	}
	if (i == 6)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
/* ������������п��ܵ�IP��ַ����ARP������߳� */
DWORD WINAPI SendArpPacket(LPVOID lpParameter)//(pcap_t *adhandle,char *ip,unsigned char *mac,char *netmask)
{
	sparam *spara = (sparam *)lpParameter;
	pcap_t *adhandle = spara->adhandle;
	char *ip = spara->ip;
	unsigned char *mac = spara->mac;
	char *netmask = spara->netmask;
	printf("ip_mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	printf("�����IP��ַΪ:%s\n", ip);
	printf("��ַ����NETMASKΪ:%s\n", netmask);
	printf("\n");
	unsigned char sendbuf[42];//arp���ṹ��С
	struct ethernet_head eh;
	struct arp_head ah;
	memset(eh.dest_mac_add, 0xff, 6);//Ŀ�ĵ�ַΪȫΪ�㲥��ַ
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
	unsigned long hisip = htonl((myip&mynetmask));
	for (int i = 0; i<HOSTNUM; i++)
	{
		ah.dest_ip_add = htonl(hisip + i);
		memset(sendbuf, 0, sizeof(sendbuf));
		memcpy(sendbuf, &eh, sizeof(eh));
		memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
		if (pcap_sendpacket(adhandle, sendbuf, 42) == 0)
		{
			//printf("\nPacketSend succeed\n");
		}
		else
		{
			printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		}
		Sleep(50);
	}
	Sleep(1000);
	flag = TRUE;
	return 0;
}
/* �������������ݰ���ȡ�������IP��ַ */
DWORD WINAPI GetLivePC(LPVOID lpParameter)//(pcap_t *adhandle)
{
	gparam *gpara = (gparam *)lpParameter;
	pcap_t *adhandle = gpara->adhandle;
	int res;
	unsigned char Mac[6];
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	while (true)
	{
		if (flag)
		{
			printf("ɨ����ϣ���������˳�!\n");
			break;
		}
		if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)
		{
			if (*(unsigned short *)(pkt_data + 12) == htons(ETH_ARP))
			{
				struct arp_packet *recv = (arp_packet *)pkt_data;
				if (*(unsigned short *)(pkt_data + 20) == htons(ARP_REPLY))
				{
					printf("-------------------------------------------\n");
					printf("IP��ַ:%d.%d.%d.%d   MAC��ַ:", recv->ah.source_ip_add & 255, recv->ah.source_ip_add >> 8 & 255, recv->ah.source_ip_add >> 16 & 255, recv->ah.source_ip_add >> 24 & 255);
					for (int i = 0; i<6; i++)
					{
						Mac[i] = *(unsigned char *)(pkt_data + 22 + i);
						printf("%02x", Mac[i]);
					}
					printf("\n");
				}
			}
		}
		Sleep(10);
	}
	return 0;
}