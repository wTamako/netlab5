#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
#include "pcap.h"
#include "stdio.h"
#include <string.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)

#pragma pack(1)
typedef struct FrameHeader_t {		//帧首部
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;
typedef struct IPHeader_t {		//IP首部
	BYTE Ver_HLen;//IP协议版本和IP首部长度：高4位为版本，低4位为首部的长度
	BYTE TOS;//服务类型
	WORD TotalLen;//总长度
	WORD ID;//标识
	WORD Flag_Segment;//标志 片偏移
	BYTE TTL;//生存周期
	BYTE Protocol;//协议
	WORD Checksum;//头部校验和
	u_int SrcIP;//源IP
	u_int DstIP;//目的IP
}IPHeader_t;
typedef struct Data_t {	//数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;
typedef struct ICMP {//ICMP报文
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;
#pragma pack()

static FILE* fp;
static void Writelog(const char* a, Data_t* t)
	{
		fprintf(fp, a);
		fprintf(fp, "\t");
		in_addr addr;
		addr.s_addr = t->IPHeader.SrcIP;
		char* temp = inet_ntoa(addr);
		fprintf(fp, "\t");
		fprintf(fp, "%s\t", temp);
		fprintf(fp, "\t");
		addr.s_addr = t->IPHeader.DstIP;
		temp = inet_ntoa(addr);
		fprintf(fp, "%s\t", temp);
		fprintf(fp, "\t");
		for (int i = 0; i < 6; i++)
			fprintf(fp, "%02x:", t->FrameHeader.SrcMAC[i]);
		fprintf(fp, "\t");
		for (int i = 0; i < 6; i++)
			fprintf(fp, "%02x:", t->FrameHeader.DesMAC[i]);
		fprintf(fp, "\n");
		//换行

	}

char ip[10][20];
char mask[10][20];
//selfmac设为00-0C-29-BD-D5-3C
BYTE selfmac[6] = { 0x00,0x0C,0x29,0xBD,0xD5,0x3C };
pcap_t* adhandle;
HANDLE hThread;
DWORD dwThreadId;
int n;
BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
#pragma pack(1)
class RouterItem//路由表表项
{
public:
	DWORD mask;//掩码
	DWORD net;//目的网络
	DWORD nextip;//下一跳
	BYTE nextmac[6];
	int type;//0为直接连接，1为用户添加
	RouterItem* nextitem;//采用链表形式存储
	RouterItem()
	{
		memset(this, 0, sizeof(*this));//全部初始化为0
	}
	void PrintItem()//打印表项内容：掩码、目的网络、下一跳IP、类型
	{
		in_addr addr;
		addr.s_addr = net;
		char* temp = inet_ntoa(addr);
		printf("%s\t", temp);
        addr.s_addr = mask;
		temp = inet_ntoa(addr);
		printf("%s\t", temp);
		addr.s_addr = nextip;
		temp = inet_ntoa(addr);
		printf("%s\n", temp);
	}
};
class RouterTable//路由表
{
public:
	RouterItem* head, * tail;
	int num;
	RouterTable()//初始化，添加直接相连的网络
	{
		head = new RouterItem;
		tail = new RouterItem;
		head->nextitem = tail;
		num = 0;
		for (int i = 0; i < 2; i++)
		{
			RouterItem* temp = new RouterItem;
			temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));//本机网卡的ip和掩码进行按位与即为所在网络
			temp->mask = inet_addr(mask[i]);
			temp->type = 0;
			this->RouterAdd(temp);
		}
	}
	void RouterAdd(RouterItem* a) // 向路由表中添加新的路由项
    {
    RouterItem* pointer; 
    // 当路由项类型为0时，即静态路由，它将被插入到链表的头部
    if (!a->type)
    {
        a->nextitem = head->nextitem; // 让新项的next指向当前head指向的第一项
        head->nextitem = a; // 更新链表头部的next指向新添加的项目
        a->type = 0; 
    }
    else // 当是即动态路由它将被插入到适当位置保持链表的排序
    {
        // 遍历链表，找到合适的插入位置（依据掩码的大小）
        for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)
        {
            // 如果新路由项的掩码小于当前项的掩码，且大于等于下一项的掩码，或者下一个位置是尾部，则停止遍历
            if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
            {
                break;
            }
        }
        a->nextitem = pointer->nextitem;
        pointer->nextitem = a; 
    }
    num++;
    } 
	void RouterDelete(DWORD temp)//路由表的删除
	{
		//寻找目标网络为temp的路由表项，并删除
		for (RouterItem* t = head; t->nextitem != tail; t = t->nextitem)
		{
			if (t->nextitem->net == temp )
			{
				if (t->nextitem->type == 0)
				{
					printf("该项不可删除\n");
					return;
				}
				else
				{
					t->nextitem = t->nextitem->nextitem;
					return;
				}
			}
		}
		printf("无该表项\n");
	}
	DWORD RouterFind(DWORD ip)//查找路由表中是否有对应的表项，有则返回下一跳IP，无则返回-1
	{
		for (RouterItem* t = head->nextitem; t != tail; t = t->nextitem)
		{
			if ((t->mask & ip) == t->net)
			{
				return t->nextip;
			}
		}
		return -1;
	}
	void print()
	{
		for (RouterItem* p = head->nextitem; p != tail; p = p->nextitem)
		{
			p->PrintItem();
		}
	}
};
struct ipandmac {
    DWORD ip;
	BYTE mac[6];
};
ipandmac ipandmacs[10];
int inum = 0;
static int FindMac(DWORD ip, BYTE mac[6])
	{
		memset(mac, 0, 6);
		for (int i = 0; i < inum; i++)
		{
			if (ip == ipandmacs[i].ip)
			{
				memcpy(mac, ipandmacs[i].mac, 6);
				return 1;
			}
		}
		return 0;
	}
#pragma pack()
bool Compare(BYTE a[6], BYTE b[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
		{
			return 0;
		}
	}
	return 1;
}
void resend(ICMP_t data, BYTE desmac[])
{
    Data_t* temp = (Data_t*)&data; 
    // 设置源MAC地址为目标MAC地址，目的MAC地址为传入的desmac，并减少TTL
    memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);
    memcpy(temp->FrameHeader.DesMAC, desmac, 6);
    temp->IPHeader.TTL -= 1;
    if (temp->IPHeader.TTL < 0)// 如果TTL小于0，则返回，不再进行转发
    {
        return;
    }
    temp->IPHeader.Checksum = 0; // 对IP头部进行校验和计算
    unsigned int sum = 0;
    WORD* t = (WORD*)&temp->IPHeader; 
    for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
    {
        sum += t[i]; // 累加IP头部的每个16位块
        // 如果出现溢出，则进行回卷操作
        while (sum >= 0x10000)
        {
            int s = sum >> 16; // 提取溢出部分
            sum -= 0x10000; // 减去溢出部分的基值
            sum += s; // 将溢出部分加回到累加器
        }
    }
    temp->IPHeader.Checksum = ~sum; // 计算最终的校验和值，取反结果存入校验和字段
    if (pcap_sendpacket(adhandle, (const u_char*)temp, 74) == 0)
    {
        Writelog("转发", temp);
    }
}
void opentxt()
{
	fp = fopen("log.txt", "a+");//文件以及打开方式
	//初始化ipandmacs[0],ip为206.1.1.2，mac地址为00-0C-29-18-FA-F4
	ipandmacs[0].ip = inet_addr("206.1.1.2");
	ipandmacs[0].mac[0] = 0x00;
	ipandmacs[0].mac[1] = 0x0C;
	ipandmacs[0].mac[2] = 0x29;
	ipandmacs[0].mac[3] = 0x18;
	ipandmacs[0].mac[4] = 0xFA;
	ipandmacs[0].mac[5] = 0xF4;
	inum++;
	//初始化ipandmacs[1],ip为206.1.2.2，mac地址为00-0C-29-DA-D2-53
	ipandmacs[1].ip = inet_addr("206.1.2.2");
	ipandmacs[1].mac[0] = 0x00;
	ipandmacs[1].mac[1] = 0x0C;
	ipandmacs[1].mac[2] = 0x29;
	ipandmacs[1].mac[3] = 0xDA;
	ipandmacs[1].mac[4] = 0xD2;
	ipandmacs[1].mac[5] = 0x53;
	inum++;
}


DWORD WINAPI Thread(LPVOID lparam)
{
    RouterTable RT = *(RouterTable*)(LPVOID)lparam;
    while (1)
    {
        pcap_pkthdr* pkt_header;
        const u_char* pkt_data;
        FrameHeader_t* header;
        while (1)
        {
            int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
            if (rtn)
            {
                // 将数据包的起始部分转换为帧头部结构体
                header = (FrameHeader_t*)pkt_data;
                // 检查目的MAC地址是否为这台机器的MAC地址，并且帧类型是否为IP数据包
                if (Compare(header->DesMAC, selfmac) && ntohs(header->FrameType) == 0x0800)
                {
                    break;
                }
            }
        }
        Data_t* data = (Data_t*)pkt_data;
        Writelog("接收", data);
        DWORD dstip = data->IPHeader.DstIP;
        // 使用路由表查找目的IP的出口
        DWORD ipexit = RT.RouterFind(dstip);
        // 如果没有找到对应出口，则继续监听下一个数据包
        if (ipexit == -1)
        {
            continue;
        }
        // 计算IP头部校验
        unsigned int sum = 0;
        WORD* t = (WORD*)&data->IPHeader;
        for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
        {
            sum += t[i];
            while (sum >> 16)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
        // 如果校验和正确，则表示IP数据报文是完整无误的
        if (sum == 0xFFFF)
        {
            // 如果目的IP不是这台机器上的任何一个IP
            if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1]))
            {
                // 进行广播地址的比较
                int t1 = Compare(data->FrameHeader.DesMAC, broadcast);
                int t2 = Compare(data->FrameHeader.SrcMAC, broadcast);
                // 如果既不是广播地址的目的MAC也不是源MAC
                if (!t1 && !t2)
                {
                    //I处理ICMP报文（该报文可能包括IP数据包头部和其他数据）
                    ICMP_t* temp_ = (ICMP_t*)pkt_data;
                    ICMP_t temp = *temp_;
                    BYTE mac[6];
                    // 如果需要直接交付
                    if (ipexit == 0)
                    {
                        FindMac(dstip, mac);
                        resend(temp, mac);
                    }
                    else if (ipexit != -1) // 非直接交付，需要查询下一跳的MAC地址
                    {
                        FindMac(ipexit, mac);
                        resend(temp, mac);
                    }
                }
            }
        }
    }
}
int main()
{
	pcap_if_t* alldevs;//指向设备链表首部的指针
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	int num = 0;//接口数量

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1)
	{
		//错误处理
		printf("获取本机设备错误");
		printf("%d\n", errbuf);
		pcap_freealldevs(alldevs);
		return 0;
	}
	int t = 0;
	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		printf("%d:", num);
		printf("%s\n", d->name);
		if (d->description != NULL)//利用d->description获取该网络接口设备的描述信息
		{
			printf("%s\n", d->description);
		}
		//获取该网络接口设备的ip地址信息
		pcap_addr_t* a; // 网络适配器的地址
		for (a = d->addresses; a != NULL; a = a->next)
		{
			switch (a->addr->sa_family)//sa_family代表了地址的类型
			{
			case AF_INET://IPV4
				printf("Address Family Name:AF_INET\t");
				if (a->addr != NULL)
				{
					//strcpy(ip, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					printf("%s\t%s\n", "IP:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					printf("%s\t%s\n", "MASK:", inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
					strcpy(ip[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					strcpy(mask[t], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
					//t++;
				}
				break;
			case AF_INET6://IPV6
				printf("Address Family Name:AF_INET6\n");
				break;
			default:
				break;
			}
			t++;
		}
	}
	if (num == 0)
	{
		printf("无可用接口\n");
		return 0;
	}
	n=1;
	num = 0;
	// 跳转到选中的网络接口号
	for (d = alldevs; num < (n - 1); num++)
	{
		d = d->next;
	}
	adhandle = pcap_open(d->name,		//设备名
		65536,		//要捕获的数据包的部分
		PCAP_OPENFLAG_PROMISCUOUS,		//混杂模式
		1000,			//超时时间
		NULL,		//远程机器验证
		errbuf		//错误缓冲池
	);
	if (adhandle == NULL)
	{
		printf("wrong!\n");
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		printf("监听：%s\n", d->description);
		pcap_freealldevs(alldevs);
	}

	for (int i = 0; i < 2; i++)
	{
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}
	opentxt();
	RouterTable RT;
	hThread = CreateThread(NULL, NULL, Thread, LPVOID(&RT), 0, &dwThreadId);

	char temp1[30];
	char temp2[30];
	char next[30];
	char net[30];
	char mask[30];
	while (1)
	{
		//当输入 route print 时，打印路由表
		scanf("%s", temp1);
		scanf("%s", temp2);
		if( strcmp(temp1,"route")==0 && strcmp(temp2,"print")==0)
		{
			RT.print();
		}
		//当输入 route add 时，添加路由表项
		else if (strcmp(temp1, "route") == 0 && strcmp(temp2, "add") == 0)
		{
			scanf("%s", net);
			scanf("%s", mask);
			scanf("%s", next);
			RouterItem* temp = new RouterItem;
			temp->net = inet_addr(net);
			temp->mask = inet_addr(mask);
			temp->nextip = inet_addr(next);
			temp->type = 1;
			RT.RouterAdd(temp);
		}
		//当输入 route delete 时，删除路由表项
		else if (strcmp(temp1, "route") == 0 && strcmp(temp2, "delete") == 0)
		{
			scanf("%s", net);
			DWORD temp=inet_addr(net);
			RT.RouterDelete(temp);
		}
		else
		{
			printf("输入错误\n");
		}
	}
	fclose(fp);
	pcap_close(adhandle);
	return 0;
}