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
	unsigned char Version_HLen;//1byte 版本类型
	unsigned char TOS;//1byte 服务类型
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



struct ethernet_head  ethernet;
struct IpHeader ip;
struct TcpHeader tcp;
struct PsdTcpHeader ptcp;
//发送时的数据修改
char * sourIP;
char * destIP;
int Result;
pcap_t *adhandle;
int ret;
struct pcap_pkthdr *header;
const u_char *pkt_data;


int main() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp and (src host 211.87.236.149)"; //自己定义ip地址即可
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
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

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

	printf("nlistening on %s...n", d->description);

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

	printf("nlistening on %s...\n", d->description);



	while ((ret = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (ret == 0) {
			/* 超时时间到 */
			printf("time over!\n");
			continue;
		}
		char buffer[18];
		if (header->len > 0) {
			printf("len:[%d]n", header->len);
			//获取mac
			rec_eth_head = (ethernet_head*)pkt_data;
			for (int j = 0; j < 6; j++){
				char * temp = (char*)malloc(sizeof(char));
				_itoa((int)(rec_eth_head->dest_mac_add[j]), temp, 16);
				printf("%s  ", temp);
			}
			printf("DestMac:\n");


			//获取包中的ip
			ip_header *ip = (ip_header *)(pkt_data + 14);
			printf("daddr:[%u.%u.%u.%u]n", ip->daddr.byte1, ip->daddr.byte2,
				ip->daddr.byte3, ip->daddr.byte4);
			if(!(ip->daddr.byte1==192&&ip->daddr.byte2==168&&ip->daddr.byte3==191&&ip->daddr.byte4==1))continue;
			printf("saddr:[%u.%u.%u.%u]n", ip->saddr.byte1, ip->saddr.byte2,
				ip->saddr.byte3, ip->saddr.byte4);

			//获取包中的tcp
			tcp_header *tcp = (tcp_header *)((u_char*)ip + (ip->ver_ihl & 0xf) * 4);
			//获取包中的数据
			char *data = (char*)((char *)tcp + (tcp->hlen) * 4);
			//获取包中的数据长度
			u_int datalen = ntohs(ip->tlen) - (ip->ver_ihl & 0xf) * 4 - (tcp->hlen) * 4;
			//打印出ip头，tcp头和数据长度
			printf("ipheader的长度%d\ntcp头的长度%d\n数据长度%d\n",
				(ip->ver_ihl & 0xf) * 4, (tcp->hlen) * 4, datalen);
			//打印出源和目的端口号
			printf("srcport:%d desport:%d\n", ntohs(tcp->src_port), ntohs(tcp->dst_port));
			//memcpy(buffer, data, datalen);
			//打印出接收到的数据
			//printf("buffer:[%s]n", buffer);
			printf("接收到的数据为%s\n", data);
			//sendHello();
		}
	}
}
