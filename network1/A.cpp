#define  _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include "pcap.h"
#include "Packet32.h"
#pragma pack(1)  //按一个字节内存对齐
#define IPTOSBUFFERS    12
#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1
#define ARP_REPLY       2
#define HOSTNUM         255
/* packet handler 函数原型*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header,
		const u_char *pkt_data);
// 函数原型
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
int SendArp(pcap_t *adhandle, char *ip, unsigned char *mac);
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac);
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);
void sendHello();
void receiveMessage();

//28字节ARP帧结构
struct arp_head {
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
struct ethernet_head {
	unsigned char dest_mac_add[6];    //目的mac地址
	unsigned char source_mac_add[6]; //源mac地址
	unsigned short type;              //帧类型
};
//arp最终包结构
struct arp_packet {
	struct ethernet_head ed;
	struct arp_head ah;
};

//IP数据头
struct ip_headerForSend  //小端模式
{
	unsigned char ihl :4;              //ip   header   length
	unsigned char version :4;          //version
	u_char tos;                //type   of   service
	u_short tot_len;            //total   length
	u_short id;                 //identification
	u_short frag_off;           //fragment   offset
	u_char ttl;                //time   to   live
	u_char protocol;           //protocol   type
	u_short check;              //check   sum
	u_int saddr;              //source   address
	u_int daddr;              //destination   address
};

//tcp数据头
struct tcp_headerForSend //小端模式
{
	u_short source;
	u_short dest;
	u_int32_t seq;
	u_int32_t ack_seq;
	u_char lenres; //
	u_char flag;	//
	u_short window;	//窗口大小
	u_short check;	//校验和
	u_short urg_ptr;	//紧急指针
};

//tcp和udp计算校验和是的伪头
struct psd_header {
	u_int32_t sourceip;       //源IP地址
	u_int32_t destip;         //目的IP地址
	u_char mbz;            //置空(0)
	u_char ptcl;           //协议类型
	u_int16_t plen;           //TCP/UDP数据包的长度(即从TCP/UDP报头算起到数据包结束的长度 单位:字节)
};

/**以太网数据头 |  IP数据头 | TCP数据头 | 数据*/
struct ethernet_packet {
	struct ethernet_head eh;
	struct ip_headerForSend iph;
	struct tcp_headerForSend tcph;
};

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

struct EthernetHeader {
	u_char DestMAC[6];
	u_char SourMAC[6];
	u_short EthType;
};
struct IpHeader {
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
/**12byte*/
struct PsdTcpHeader {
	unsigned long SourceAddr;
	unsigned long DestinationAddr;
	char Zero;
	char Protcol;
	unsigned short TcpLen;
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

/**记录扫描到的MAC和IP对应的信息*/
struct MacMapIP {
	unsigned char Mac[6];
	unsigned long IP[4];
} Machines[256];
/**来记录是否是已经扫描完成了*/
boolean scanFinished = false;
/**发送的机器在Map表里对应的序号*/
int sendIndex;
/**机器本身的MAC*/
unsigned char selfMAC[6];
int countMachine = 0;
ethernet_head * rec_eth_head;
//发送时的数据修改
char * sourIP;
char * destIP;

struct EthernetHeader ethernet;
struct IpHeader ip;
struct TcpHeader tcp;
struct PsdTcpHeader ptcp;
int Result;
unsigned char SendBuffer[200];
unsigned char *SendBuffer2;
char TcpData[] = "Hello,this is FindA";

pcap_t *adhandle;

pcap_if_t *alldevs;
pcap_if_t *d;
int inum;
int i = 0;
char errbuf[PCAP_ERRBUF_SIZE];
u_int netmask;
struct bpf_program fcode;
char *ip_addr;
char *ip_netmask;
unsigned char *ip_mac;
HANDLE sendthread;
HANDLE recvthread;
int main() {

	ip_addr = (char *) malloc(sizeof(char) * 16); //申请内存存放IP地址
	if (ip_addr == NULL) {
		printf("申请内存存放IP地址失败!\n");
		return -1;
	}
	ip_netmask = (char *) malloc(sizeof(char) * 16); //申请内存存放NETMASK地址
	if (ip_netmask == NULL) {
		printf("申请内存存放NETMASK地址失败!\n");
		return -1;
	}
	ip_mac = (unsigned char *) malloc(sizeof(unsigned char) * 6); //申请内存存放MAC地址
	if (ip_mac == NULL) {
		printf("申请内存存放MAC地址失败!\n");
		return -1;
	}
	/* 获取本机设备列表*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* 打印列表*/
	printf("[本机网卡列表：]\n");
	for (d = alldevs; d; d = d->next) {
		printf("%d) %s\n", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0) {
		printf("\n找不到网卡！请确认是否已安装WinPcap.\n");
		return -1;
	}
	printf("\n");
	printf("请选择要打开的网卡号(1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i) {
		printf("\n该网卡号超过现有网卡数!请按任意键退出…\n");
		getchar();
		getchar();
		/* 释放设备列表*/
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* 跳转到选中的适配器*/
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
		;
	/* 打开设备*/
	if ((adhandle = pcap_open(d->name,          // 设备名
			65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
			PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
			1000,             // 读取超时时间
			NULL,             // 远程机器验证
			errbuf            // 错误缓冲池
			)) == NULL) {
		fprintf(stderr, "\n无法读取该适配器. 适配器%s 不被WinPcap支持\n", d->name);
		/* 释放设备列表*/
		pcap_freealldevs(alldevs);
		return -1;
	}
	ifget(d, ip_addr, ip_netmask);            //获取所选网卡的基本信息--掩码--IP地址
	GetSelfMac(adhandle, ip_addr, ip_mac);         //输入网卡设备句柄网卡设备ip地址获取该设备的MAC地址
	sp.adhandle = adhandle;
	sp.ip = ip_addr;
	sp.mac = ip_mac;
	sp.netmask = ip_netmask;
	gp.adhandle = adhandle;
	printf("\nlistening on 网卡%d ...\n", inum);

	sendHello();

	Result = pcap_sendpacket(adhandle, SendBuffer,
			sizeof(struct EthernetHeader) + sizeof(struct IpHeader)
					+ sizeof(struct TcpHeader) + strlen(TcpData));
	printf("The length is %d\n",
			sizeof(struct EthernetHeader) + sizeof(struct IpHeader)
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

	/* 释放设备列表*/
	pcap_freealldevs(alldevs);
	getchar();
	getchar();
	return 0;
}
/* 获取可用信息*/
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

void sendHello() {

	memset(&ethernet, 0, sizeof(ethernet));
	BYTE destmac[8];
	destmac[0] = 0x74;
	destmac[1] = 0xe5;
	destmac[2] = 0x0b;
	destmac[3] = 0xf4;
	destmac[4] = 0xbd;
	destmac[5] = 0x07;
//	for (int i = 0; i < 6; i++) {
//		destmac[i] = Machines[sendIndex].Mac[i];
//	}
	printf("sendindex%d\n",sendIndex);
	memcpy(ethernet.DestMAC, destmac, 6);
	BYTE hostmac[8];
	for (int i = 0; i < 6; i++) {
		hostmac[i] = selfMAC[i];
	}

	//hostmac[0] = 0x74;
	//hostmac[1] = 0xe5;
	//hostmac[2] = 0x0b;
	//hostmac[3] = 0xf4;
	//hostmac[4] = 0xbd;
	//hostmac[5] = 0x07;
	memcpy(ethernet.SourMAC, hostmac, 6);
	ethernet.EthType = htons(0x0800);
	//加入以太网帧头
	memcpy(&SendBuffer, &ethernet, sizeof(struct EthernetHeader));
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
	ip.SourceAddr = inet_addr("211.87.237.250");

//	ip.DestinationAddr=inet_addr()
	ip.DestinationAddr = inet_addr("192.168.191.1");
	//加入ip头
	memcpy(&SendBuffer[sizeof(struct EthernetHeader)], &ip, 20);
	tcp.DstPort = htons(88);
	tcp.SrcPort = htons(1000);
	tcp.SequenceNum = htonl(11);
	tcp.Acknowledgment = 0;
	tcp.HdrLen = 0x50;
	tcp.Flags = 0x18;
	tcp.AdvertisedWindow = htons(512);
	tcp.UrgPtr = 0;
	tcp.Checksum = 0;
//加入tcp头
	memcpy(&SendBuffer[sizeof(struct EthernetHeader) + 20], &tcp, 20);
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
	//重新校验
	memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader),
			&tcp, sizeof(struct TcpHeader));
	memcpy(
			SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader)
					+ sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	memset(TempBuffer, 0, sizeof(TempBuffer));
	memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
	ip.Checksum = checksum((USHORT*) (TempBuffer), sizeof(struct IpHeader));
	memcpy(SendBuffer + sizeof(struct EthernetHeader), &ip,
			sizeof(struct IpHeader));
//	int ss = sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData);
//	SendBuffer2 =(unsigned char *) malloc(sizeof(unsigned char *)*ss);
//	memcpy(SendBuffer2,SendBuffer,ss);
}

/* 将数字类型的IP地址转换成字符串类型的*/
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
/* 获取自己主机的MAC地址
 广播一个arp包，如果接收到的包的源ip是自己设定的那个， 那么就是自己的包，那么，从这个包里可以找到自己的mac

 */
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac) {
	unsigned char sendbuf[42];            //arp包结构大小
	int i = -1;
	int res;
	struct ethernet_head eh;
	struct arp_head ah;
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	memset(eh.dest_mac_add, 0xff, 6);            //目的地址为全为广播地址
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
			printf("获取自己主机的MAC地址成功!\n");
			break;
		}
	}
	if (i == 6) {
		return 1;
	} else {
		return 0;
	}
}
