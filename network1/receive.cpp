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


void receiveMessage();
void sendHello();





unsigned char SendBuffer[200];


//14字节以太网帧结构
struct ethernet_head
{
	unsigned char dest_mac_add[6];    //目的mac地址
	unsigned char source_mac_add[6]; //源mac地址
	unsigned short type;              //帧类型
};
ethernet_head * rec_eth_head;
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
struct TcpHeader
{
	unsigned short SrcPort;	//2byte
	unsigned short DstPort;	//2byte
	unsigned int SequenceNum;			//4byte
	unsigned int Acknowledgment;	//4byte
	unsigned char HdrLen;			//1byte
	unsigned char Flags;			//1byte
	unsigned short AdvertisedWindow;		//2byte
	unsigned short Checksum;				//2byte
	unsigned short UrgPtr;						//2byte
};					//20byte
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

struct PsdTcpHeader
{
	unsigned long SourceAddr;
	unsigned long DestinationAddr;
	char Zero;
	char Protcol;
	unsigned short TcpLen;
};

char TcpData[] = "Hello,Find,this is Lucy";


struct ethernet_head  ethernet;
struct IpHeader ip;
struct TcpHeader tcp;
struct PsdTcpHeader ptcp;
//发送时的数据修改
char * sourIP;
char * destIP;
int Result;




	pcap_t *adhandle;
int main() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp and (src host 192.168.191.1)"; //自己定义ip地址即可
	struct bpf_program fcode;

	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
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
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
		;

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name, // 设备名
			65535, // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
			PCAP_OPENFLAG_PROMISCUOUS, // 混杂模式
			1000, // 读取超时时间
			NULL, // 远程机器验证
			errbuf // 错误缓冲池
			)) == NULL) {
		fprintf(stderr,
				"\nUnable to open the adapter. %s is not supported by WinPcap\n",
				d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);






	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("datalink:[%d]\n", pcap_datalink(adhandle));
	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask =
				((struct sockaddr_in *) (d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;

	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		fprintf(stderr,
				"\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		int x;
		scanf("%d", &x);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);




	receiveMessage();
	
	//sendHello();
	/* 释放设备列表 */
	pcap_freealldevs(alldevs);


	return 0;
}

void receiveMessage(){
	/* 开始捕获 */
	int ret;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	boolean getit = false;
	while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0 && !getit) {
		if (ret == 0) {
			/* 超时时间到 */
			printf("time over!\n");
			continue;
		}
		char buffer[18];
		if (header->len > 0) {
			printf("len:[%d]\n", header->len);
			//获取mac
			rec_eth_head= (ethernet_head*)pkt_data;
			
			printf("DestMac:\n");
			for (int j = 0; j<6; j++){
				char * temp=(char*)malloc(sizeof(char));
				_itoa((int)(rec_eth_head->dest_mac_add[j]), temp, 16);
				printf("%s  ", temp);
			}
			


			//获取包中的ip
			ip_header *ip = (ip_header *)(pkt_data + 14);
			printf("daddr:[%u.%u.%u.%u]\n", ip->daddr.byte1, ip->daddr.byte2,
				ip->daddr.byte3, ip->daddr.byte4);
			/*sourIP=(char *)malloc(sizeof(char*));
			strcat(sourIP,ip->daddr.byte1+".");
			strcat(sourIP,ip->daddr.byte2+".");
			strcat(sourIP,ip->daddr.byte3+".");
			strcat(sourIP,ip->daddr.byte4+"");*/


			printf("***********sourip**********\n%s", sourIP);
			printf("saddr:[%u.%u.%u.%u]\n", ip->saddr.byte1, ip->saddr.byte2,
				ip->saddr.byte3, ip->saddr.byte4);
		/*	destIP=(char *)malloc(sizeof(char *));
			strcat(destIP,ip->daddr.byte1+".");
			strcat(destIP,ip->daddr.byte2+".");
			strcat(destIP,ip->daddr.byte3+".");
			strcat(destIP,ip->daddr.byte4+"");
*/

			tcp_header *tcp = (tcp_header *)((u_char*)ip
				+ (ip->ver_ihl & 0xf) * 4);

			char *data = (char*)((char *)tcp + (tcp->hlen) * 4);
			u_int datalen = ntohs(ip->tlen) - (ip->ver_ihl & 0xf) * 4
				- (tcp->hlen) * 4;
			printf("ipheader的长度%d\ntcp头的长度%d\n数据长度%d\n",
				(ip->ver_ihl & 0xf) * 4, (tcp->hlen) * 4, datalen);
			memcpy(buffer, data, datalen);
			printf("buffer:[%s]\n", buffer);
			getit = true;
			Sleep(4000);
			sendHello();
		}
	}
}
void sendHello(){
	memset(&ethernet, 0, sizeof(ethernet));
	memcpy(ethernet.dest_mac_add, rec_eth_head->source_mac_add, 6);
	memcpy(ethernet.source_mac_add, rec_eth_head->dest_mac_add, 6);
	ethernet.type = htons(0x0800);
	memcpy(&SendBuffer, &ethernet, sizeof(struct ethernet_head));
	ip.Version_HLen = 0x45;
	ip.TOS = 0;
	ip.Length = htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
	ip.Ident = htons(1);
	ip.Flags_Offset = 0;
	ip.TTL = 128;
	ip.Protocol = 6;
	ip.Checksum = 0;
	//printf("sip:%s\ndip%s\n", sourIP, destIP);
	ip.SourceAddr = inet_addr("211.87.237.200");
	ip.DestinationAddr = inet_addr("211.87.237.201");
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
	memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &tcp, sizeof(struct TcpHeader));
	memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));

	memcpy(SendBuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader), &tcp, sizeof(struct TcpHeader));
	memcpy(SendBuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	memset(TempBuffer, 0, sizeof(TempBuffer));
	memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
	ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
	memcpy(SendBuffer + sizeof(struct ethernet_head), &ip, sizeof(struct IpHeader));
	Result = pcap_sendpacket(adhandle, SendBuffer, sizeof(struct ethernet_head) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
		printf("The length is %d\n", sizeof(struct ethernet_head) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
		if (Result != 0)
		{
			printf("Send Error!\n");
		}
		else
		{
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

		printf("\n\n************************\nYou reply message successfully!");
		getchar();
		getchar();
}

