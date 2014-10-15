#define  _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include "pcap.h"
#include "Packet32.h"
#include "tcp.h"


#pragma pack(1)  //按一个字节内存对齐
#define IPTOSBUFFERS    12
#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1
#define ARP_REPLY       2
#define HOSTNUM         255
/* packet handler 函数原型*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
// 函数原型
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
int SendArp(pcap_t *adhandle, char *ip, unsigned char *mac);
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac);
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);

//28字节ARP帧结构
struct arp_head
{
	unsigned short hardware_type;    //硬件类型
	unsigned short protocol_type;    //协议类型
	unsigned char hardware_add_len; //硬件地址长度
	unsigned char protocol_add_len; //协议地址长度
	unsigned short operation_field; //操作字段
	unsigned char source_mac_add[6]; //源mac地址
	unsigned long source_ip_add;    //源ip地址
	unsigned char dest_mac_add[6]; //目的mac地址
	unsigned long dest_ip_add;      //目的ip地址
};

//14字节以太网帧结构
struct ethernet_head
{
	unsigned char dest_mac_add[6];    //目的mac地址
	unsigned char source_mac_add[6]; //源mac地址
	unsigned short type;              //帧类型
};
//arp最终包结构
struct arp_packet
{
	struct ethernet_head ed;
	struct arp_head ah;
};

////IP数据头  
//struct ip_header  //小端模式  
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

//tcp数据头  
struct tcp_header2 //小端模式  
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

//tcp和udp计算校验和是的伪头  
struct psd_header {
	u_int32_t   sourceip;       //源IP地址  
	u_int32_t   destip;         //目的IP地址  
	u_char      mbz;            //置空(0)  
	u_char      ptcl;           //协议类型  
	u_int16_t   plen;           //TCP/UDP数据包的长度(即从TCP/UDP报头算起到数据包结束的长度 单位:字节)  
};

/**以太网数据头 |  IP数据头 | TCP数据头 | 数据*/
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

	ip_addr = (char *)malloc(sizeof(char) * 16);//申请内存存放IP地址
	if (ip_addr == NULL)
	{
		printf("申请内存存放IP地址失败!\n");
		return -1;
	}
	ip_netmask = (char *)malloc(sizeof(char) * 16);//申请内存存放NETMASK地址
	if (ip_netmask == NULL)
	{
		printf("申请内存存放NETMASK地址失败!\n");
		return -1;
	}
	ip_mac = (unsigned char *)malloc(sizeof(unsigned char) * 6);//申请内存存放MAC地址
	if (ip_mac == NULL)
	{
		printf("申请内存存放MAC地址失败!\n");
		return -1;
	}
	/* 获取本机设备列表*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* 打印列表*/
	printf("[本机网卡列表：]\n");
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
		printf("\n找不到网卡！请确认是否已安装WinPcap.\n");
		return -1;
	}
	printf("\n");
	printf("请选择要打开的网卡号(1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\n该网卡号超过现有网卡数!请按任意键退出…\n");
		getchar();
		getchar();
		/* 释放设备列表*/
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* 跳转到选中的适配器*/
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);
	/* 打开设备*/
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
		)) == NULL)
	{
		fprintf(stderr, "\n无法读取该适配器. 适配器%s 不被WinPcap支持\n", d->name);
		/* 释放设备列表*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on 网卡%d ...\n", inum);








	u_int netmask;
	char packet_filter[] = "tcp and (src host *.*.*.*)";//自己定义ip地址即可
	struct bpf_program fcode;


	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "nThis program works only on Ethernet networks.n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("datalink:[%d]n", pcap_datalink(adhandle));
	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;


	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "nUnable to compile the packet filter. Check the syntax.n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		int x;
		scanf("%d", &x);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "nError setting the filter.n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);



	/* 开始捕获 */
	int ret;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;


	while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (ret == 0)
		{
			/* 超时时间到 */
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
/* 获取可用信息*/
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

/* 将数字类型的IP地址转换成字符串类型的*/
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
/* 获取自己主机的MAC地址
广播一个arp包，如果接收到的包的源ip是自己设定的那个， 那么就是自己的包，那么，从这个包里可以找到自己的mac

*/
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac)
{
	unsigned char sendbuf[42];//arp包结构大小
	int i = -1;
	int res;
	struct ethernet_head eh;
	struct arp_head ah;
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	memset(eh.dest_mac_add, 0xff, 6);//目的地址为全为广播地址
	memset(eh.source_mac_add, 0x0f, 6);
	memset(ah.source_mac_add, 0x0f, 6);
	memset(ah.dest_mac_add, 0x00, 6);
	eh.type = htons(ETH_ARP);
	ah.hardware_type = htons(ARP_HARDWARE);
	ah.protocol_type = htons(ETH_IP);
	ah.hardware_add_len = 6;
	ah.protocol_add_len = 4;
	ah.source_ip_add = inet_addr("100.100.100.100"); //随便设的请求方ip
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
			printf("获取自己主机的MAC地址成功!\n");
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
/* 向局域网内所有可能的IP地址发送ARP请求包线程 */
DWORD WINAPI SendArpPacket(LPVOID lpParameter)//(pcap_t *adhandle,char *ip,unsigned char *mac,char *netmask)
{
	sparam *spara = (sparam *)lpParameter;
	pcap_t *adhandle = spara->adhandle;
	char *ip = spara->ip;
	unsigned char *mac = spara->mac;
	char *netmask = spara->netmask;
	printf("ip_mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	printf("自身的IP地址为:%s\n", ip);
	printf("地址掩码NETMASK为:%s\n", netmask);
	printf("\n");
	unsigned char sendbuf[42];//arp包结构大小
	struct ethernet_head eh;
	struct arp_head ah;
	memset(eh.dest_mac_add, 0xff, 6);//目的地址为全为广播地址
	memcpy(eh.source_mac_add, mac, 6);
	memcpy(ah.source_mac_add, mac, 6);
	memset(ah.dest_mac_add, 0x00, 6);
	eh.type = htons(ETH_ARP);
	ah.hardware_type = htons(ARP_HARDWARE);
	ah.protocol_type = htons(ETH_IP);
	ah.hardware_add_len = 6;
	ah.protocol_add_len = 4;
	ah.source_ip_add = inet_addr(ip); //请求方的IP地址为自身的IP地址
	ah.operation_field = htons(ARP_REQUEST);
	//向局域网内广播发送arp包
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
/* 分析截留的数据包获取活动的主机IP地址 */
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
			printf("扫描完毕，按任意键退出!\n");
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
					printf("IP地址:%d.%d.%d.%d   MAC地址:", recv->ah.source_ip_add & 255, recv->ah.source_ip_add >> 8 & 255, recv->ah.source_ip_add >> 16 & 255, recv->ah.source_ip_add >> 24 & 255);
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