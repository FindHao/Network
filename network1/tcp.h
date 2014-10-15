#include <WinSock2.h>
/* 4字节的IP地址 */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

/* IPv4 首部 */

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
	u_char ver_ihl; // 版本 (4 bits) + 首部长度 (4 bits)		1byte
	u_char tos; // 服务类型(Type of service)					1byte
	u_short tlen; // 总长(Total length)							2byte
	u_short identification; // 标识(Identification)			2byte
	u_short flags_fo; // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)	2byte
	u_char ttl; // 存活时间(Time to live)						1byte
	u_char proto; // 协议(Protocol)								1byte
	u_short crc; // 首部校验和(Header checksum)			2byte
	ip_address saddr; // 源地址(Source address)				4byte
	ip_address daddr; // 目的地址(Destination address)	4byte
	u_int op_pad; // 选项与填充(Option + Padding)			4byte+
} ip_header;															//24byte+