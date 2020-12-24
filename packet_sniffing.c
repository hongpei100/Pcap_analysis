#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip6.h>
#include<net/ethernet.h>
#include<arpa/inet.h>
#include<netinet/ether.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/if_ether.h>
#include<sys/stat.h>
#include<time.h>
#include<unistd.h>
#include<signal.h>
#include<pcap.h>
#include<linux/ipv6.h>

#define BUFSIZE 10240

int num = 0;

short int ether_handler( unsigned char* arg, const struct pcap_pkthdr* header, const unsigned char* content )
{
	struct ether_header* ptr_ether; //指向乙太網路的結構

	// start with the ethernet header
	ptr_ether = ( struct ether_header* )content;
	
	printf("ethernet header:\n"); //利用ether_ntoa轉換函式,轉換出pointer所指的值
	printf("\tsource MAC addr. :       %s\n", ether_ntoa( ( const struct ether_addr* )&ptr_ether->ether_shost ) );
	printf("\tdestination MAC addr. :  %s\n", ether_ntoa( ( const struct ether_addr* )&ptr_ether->ether_dhost ) );


	// check to see if ip packet exists
	printf("\tpacket type: "); 
	if( ntohs( ptr_ether->ether_type ) == ETHERTYPE_IP ) //nthos = 轉換netshort,從networkbyte轉成host byte // 檢驗ethernet type類型
	{
		printf("IP");
	}
	else if( ntohs( ptr_ether->ether_type ) == ETHERTYPE_ARP )
	{
		printf("ARP");
	}
	else if( ntohs( ptr_ether->ether_type ) == ETHERTYPE_REVARP )
	{
		printf("REVARP");
	}
	else if( ntohs( ptr_ether->ether_type ) == ETHERTYPE_IPV6 )
	{
		printf("IPV6");
	}
	else
	{
		printf("?");
	}

	printf("\n");
	return ptr_ether->ether_type; //return ethernet type
}

void tcp_handler( const struct pcap_pkthdr* header, const unsigned char* content )
{
	struct ip* ip_header = ( struct ip* )( content + ETHER_HDR_LEN );
	struct tcphdr* tcp_header = ( struct tcphdr* )( content + ETHER_HDR_LEN + ( ip_header->ip_hl << 2 ) );

	unsigned int port_src = ntohs( tcp_header->th_sport ); //tcp source port
	unsigned int port_dst = ntohs( tcp_header->th_dport ); //tcp desti port

	printf("TCP handler: \n");
	printf("\tsource port:       %8d\n", port_src ); //port has 8 bit at most
	printf("\tdestination port:  %8d\n", port_dst ); 
	
	return ;
}

void udp_handler( const struct pcap_pkthdr* header, const unsigned char* content )
{
	struct ip* ip_header = ( struct ip* )( content + ETHER_HDR_LEN );
	struct udphdr* udp_header = ( struct udphdr* )( content + ETHER_HDR_LEN + ( ip_header->ip_hl << 2 ) );

	unsigned int port_src = ntohs( udp_header->uh_sport ); //udp source port
	unsigned int port_dst = ntohs( udp_header->uh_dport ); //udp desti port

	printf("UDP handler: \n");
	printf("\tsource port:       %8d\n", port_src ); //port has 8 bits
	printf("\tdestination port:  %8d\n", port_dst );
	
	return ;
}

void ip_handler( const struct pcap_pkthdr* header, const unsigned char* content )
{
	// get IP information with ethernet header offset
	struct ip* ip_header = ( struct ip* )( content + ETHER_HDR_LEN );
	
	unsigned int version = ip_header->ip_v;
	unsigned char protocol = ip_header->ip_p;

	printf("IP handler:\n");
	printf("\tversion: %d\n", version );
	printf("\tsource IP addr. :      %15s\n", inet_ntoa( ip_header->ip_src ) );
	printf("\tdestination IP addr. : %15s\n", inet_ntoa( ip_header->ip_dst ) );

	printf("\tprotocol: ");
	if( protocol == IPPROTO_UDP ) //檢驗IP接收到給下一層的封包是TCP或UDP或ICMP
	{
		printf("UDP\n");
		udp_handler( header, content );
	}
	else if( protocol == IPPROTO_TCP )
	{
		printf("TCP\n");
		tcp_handler( header, content );
	}
	else if( protocol == IPPROTO_ICMP )
	{
		printf("ICMP\n");
	}
	
	return ;
}

void print_ipv6_addr( unsigned char* addr )
{
	for( int i = 0; i < 16; i++ )
	{
		printf("%02x", addr[ i ] );

		if( ( i > 0 && i % 2 != 0 ) && i < 15 )
			printf(":");
	}

	printf("\n");
	return ;
}

void ip6_handler( const struct pcap_pkthdr* header, const unsigned char* content )
{
	struct ip6_hdr* ipv6_header = ( struct ip6_hdr* )( content + ETHER_HDR_LEN );
	
	char* buffer_src = ( char* )malloc( sizeof( char ) * 64 );
	char* buffer_dst = ( char* )malloc( sizeof( char ) * 64 );

	printf("IPV6 handler:\n"); //如果是IP6就特別印出這個版本
	printf("source IP addr. :      ");
	print_ipv6_addr( ( unsigned char* )&ipv6_header->ip6_src );
	printf("destination IP addr. : ");
	print_ipv6_addr( ( unsigned char* )&ipv6_header->ip6_dst );
	

	free( buffer_src );
	free( buffer_dst );
	return ;
}

static void Pcap_Handler( unsigned char* arg, const struct pcap_pkthdr* header, const unsigned char* content)
{
	time_t time_total = header->ts.tv_sec + ( header->ts.tv_usec * 1000000 );
	
	num++;
	printf("No.%d Packet:\n",num);
	printf("========== Packet Start ==========\n"); //Pcap列印,第一層先處理IP封包
	printf("time: %s", ctime( &time_total ) );
	printf("caplen: %d, len: %d\n", header->caplen, header->len );
	
	// ethernet information
	short type = ether_handler( arg, header, content );

	if( ntohs( type ) == ETHERTYPE_IP )
	{

		ip_handler( header, content );
	}
	else if( ntohs( type ) == ETHERTYPE_IPV6 )
	{
		ip6_handler( header, content );
	}
	else
		printf("else\n");
	

	printf("=========== Packet End ===========\n\n");
	return ;
}

int main( int argc, char** argv )
{
	FILE* fp_pcap = NULL;
	FILE* fp_output = NULL;

	char* error_buffer = ( char* )malloc( sizeof( char )*BUFSIZE );
	
	int ret;

	// ---------- open pcap ----------
	pcap_t* ptr_handle = pcap_open_offline( "udp.pcap", error_buffer );

	if( ptr_handle == NULL )
	{
		perror("Error Detected: Can't find pcap file\n");
		exit(0);
	}

	// ---------- call function( handler ) ----------
	ret = pcap_loop( ptr_handle, 0, Pcap_Handler, NULL ); //迭代利用call backfunction處理Pcap資料


	// ---------- clean up ----------
	free( error_buffer );

	return 0;
}

