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
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp and (src host 192.168.191.1)";//�Լ�����ip��ַ����
	struct bpf_program fcode;


	/* ��ȡ�����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת��ѡ�е������� */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* ���豸 */
	if ((adhandle = pcap_open(d->name, // �豸��
		65535, // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS, // ����ģʽ
		1000, // ��ȡ��ʱʱ��
		NULL, // Զ�̻�����֤
		errbuf // ���󻺳��
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...n", d->description);


	/* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("datalink:[%d]\n", pcap_datalink(adhandle));
	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;


	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		int x;
		scanf("%d", &x);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("nlistening on %s...\n", d->description);

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
			printf("time over!\n");
			continue;
		}
		char buffer[20];
		if (header->len > 0)
		{
			printf("len:[%d]n", header->len);
			ip_header *ip = (ip_header *)(pkt_data + 14);
			printf("daddr:[%u.%u.%u.%u]n", ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);
			printf("saddr:[%u.%u.%u.%u]n", ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4);
			tcp_header *tcp = (tcp_header *)((u_char*)ip + (ip->ver_ihl & 0xf) * 4);
			char *data = (char*)((char *)tcp + (tcp->hlen) * 4) + 58;
			u_int datalen = 20;


			memcpy(buffer, data, datalen);
			printf("buffer:[%s]n", buffer + 20);
		}

	}
	return 0;
}