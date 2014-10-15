#include <WinSock2.h>
/* 4�ֽڵ�IP��ַ */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

/* IPv4 �ײ� */

typedef struct header_tcp
{
	u_short src_port;
	u_short dst_port;
	u_int seq;
	u_int ack_seq;
	u_short doff : 4, hlen : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
	u_short window;
	u_short check;
	u_short urg_ptr;
}tcp_header;
typedef struct ip_header
{
	u_char ver_ihl; // �汾 (4 bits) + �ײ����� (4 bits)		1byte
	u_char tos; // ��������(Type of service)					1byte
	u_short tlen; // �ܳ�(Total length)							2byte
	u_short identification; // ��ʶ(Identification)			2byte
	u_short flags_fo; // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)	2byte
	u_char ttl; // ���ʱ��(Time to live)						1byte
	u_char proto; // Э��(Protocol)								1byte
	u_short crc; // �ײ�У���(Header checksum)			2byte
	ip_address saddr; // Դ��ַ(Source address)				4byte
	ip_address daddr; // Ŀ�ĵ�ַ(Destination address)	4byte
	u_int op_pad; // ѡ�������(Option + Padding)			4byte+
} ip_header;															//24byte+