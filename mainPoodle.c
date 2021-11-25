

#define APP_NAME		"sniffer"
#define APP_DESC		"Sniffer libpcap"
#define APP_COPYRIGHT	
#define APP_DISCLAIMER	
#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ec.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <net/if.h>
static char saved_status;
#define SNAP_LEN 1518

#define SIZE_ETHERNET 14
#define TCP_HEADER_SIZE 20



struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_ip {
        u_char  ip_hl;                 
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   
        u_short ip_sum;                 
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_hl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_hl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2  & 0xf0 )>> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
//pthread_t pthrec ,pthsend;
	pcap_t *handle;
	libnet_t *lnet;	
	char *dev = NULL;			
	char errbuf[PCAP_ERRBUF_SIZE];
	char errbuf_lnet[LIBNET_ERRBUF_SIZE];	
struct sniff_ssl {
	u_short ssl_contentType;
	u_char ssl_version;
	u_char ssl_len;
	};
void got_packet(u_char *args, const struct pcap_pkthdr *header,  u_char *packet);
void enable_ip_forward();
void disable_ip_forward();
void print_payload( u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_app_banner(void);
void print_app_banner(void)
{
return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	//int i;
	//int gap;
	//const u_char *ch;
	//const u_char *temp1;
//const u_char *temp2;
//const u_char *temp3;
//const u_char *temp4;
//	printf("%05d   ", offset);
	//ch = payload;
	//temp1 =payload;
	//temp2 =payload;
	//temp3 =payload;
	//if(len==0){
	//	return;
	//	}
	//temp4 =payload;
	//if( *(temp3)==0x17 && *(++temp3)==0x03 && *(++temp3)==0x00){
	//		printf("client Data ");
	//	}
	//for(i = 0; i < len; i++) {
			//if(*(temp1)==0x16 && *(++temp1)==0x03 && *(++temp1)==0x00 &&
		//*(temp1+3)==0x10){
			//printf("client key exchange");
			//printf("%02x ", *ch);
		//++ch;
		//}
			//if(*(temp2)==0x14 && *(++temp2)==0x03 && *(++temp2)==0x00 &&
		//*(temp2+3)==0x00){
			//printf("change cipher spec ");
			//printf("%02x ", *ch);
		//++ch;
		//}
			
		//printf("%02x ", *ch);
		//++ch;
		//if(*(temp4)==0x16 && *(++temp4)==0x03 && *(++temp4)==0x00 &&
		//*(temp4+3)==0x01){
		//	printf("client hello ");}
			//printf("%02x ", *ch);
		//++ch;
		
		/* print extra space after 8th byte for visual aid */
		//if (i == 7){
		//	printf(" ");
		//}
		//if(i==15){
			//printf("\n");}
	//}
	/* print space to handle line less than 8 bytes */
	//if (len < 8)
		//printf(" ");
	
	/* fill hex gap with spaces if not full line */
	//if (len < 16) {
	//	gap = 16 - len;
	//	for (i = 0; i < gap; i++) {
			//printf("   ");
		//}
	//}
	//printf("   ");
	
	
	/* ascii (if printable) */
	//ch = payload;
	//for(i = 0; i < len; i++) {
		//if (isprint(*ch))
		//	printf("%c", *ch);
		//else
			//printf(".");
		//ch++;


	//printf("\n");

return;
}


void print_payload( u_char *payload, int len)
{
			
	 u_char *ch = payload;
	 u_char *temp3;
	 ch = payload;
	 temp3 =payload;
	 	if (len <= 0){
		return;
	}
	 if( *(temp3++)==0x16 && *(temp3++)==0x03 && *(temp3++)==0x00 ){
			printf("client hello ");
			printf("%02x",*(ch));
						//printf("\n");
						//printf("%02x",*(ch+len-1));
						//*(ch+len-1)=*(temp2-25);
						//pcap_sendpacket();
						
//printf("%x02",*(ch+len-1));
		}
		int i;
		for( i = 0; i < len; i++) {
			//if(*(temp1)==0x16 && *(++temp1)==0x03 && *(++temp1)==0x00 &&
		//*(temp1+3)==0x10){
			//printf("client key exchange");
			//printf("%02x ", *ch);
		//++ch;
		//}
			//if(*(temp2)==0x14 && *(++temp2)==0x03 && *(++temp2)==0x00 &&
		//*(temp2+3)==0x00){
			//printf("change cipher spec ");
			//printf("%02x ", *ch);
		//++ch;
		//}
			
		printf("%02x ", *ch);
		++ch;
		//if(*(temp4)==0x16 && *(++temp4)==0x03 && *(++temp4)==0x00 &&
		//*(temp4+3)==0x01){
		//	printf("client hello ");}
			//printf("%02x ", *ch);
		//++ch;
		
		/* print extra space after 8th byte for visual aid */
		if (i == 7){
			printf(" ");
		}
		if(i==15){
			printf("\n");
		}
	}
		
    //const u_char *sslch=sslData;

	//if (len <= line_width) {
		//print_hex_ascii_line(ch, len, offset);
		//return;
	//}


	//for ( ;; ) {
		//line_len = line_width % len_rem;
		//print_hex_ascii_line(ch, line_len, offset);
		//len_rem = len_rem - line_len;
		//ch = ch + line_len;
		//offset = offset + line_width;
		//if (len_rem <= line_width) {
			//print_hex_ascii_line(ch, len_rem, offset);
			//break;
		//}
	//}

return;
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, u_char *packet)
{

	static int count = 1; 
	struct sniff_tcp *tcp; 
	struct sniff_ip *ip;                  
    struct libnet_ipv4_hdr *ip1;
	struct libnet_tcp_hdr *tcp1;
	libnet_t *lnet;
	int size_ip;
	int size_tcp;
	int size_payload;
	u_char *option;
	int option_s;
	u_int32_t seq, win,dip;
				//if(lnet==-1){
				//libnet_destroy(lnet);
				//}
	ip1 = (struct libnet_ipv4_hdr *)(packet+SIZE_ETHERNET);
    size_ip = IP_HL(ip1)*4;
	tcp1 = (struct libnet_tcp_hdr *)(packet +SIZE_ETHERNET+ size_ip);
	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	
     size_tcp = TH_OFF(tcp)*4;
	 seq = ntohl(tcp1->th_seq);
	 win = ntohs(tcp1->th_win);     
	 u_char *payload;  
	 libnet_ptag_t *t;
	
	printf("\nPacket number %d:\n", count);
	count++;
	printf("size of ip --%d:",size_ip);

	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	printf("       From: %s\n", inet_ntoa(ip1->ip_src));
	printf("         To: %s\n", inet_ntoa(ip1->ip_dst));
	printf("   Src port: %d\n", ntohs(tcp1->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp1->th_dport));
	printf("size of tcp ---:%d:",size_tcp);
	size_payload = ntohs(ip1->ip_len) - (size_ip + size_tcp);
	printf("   Payload (%d bytes):\n", size_payload);

	if(strcmp(inet_ntoa(ip1->ip_src),"192.168.0.223")==0 &&
	 strcmp(inet_ntoa(ip1->ip_dst),"217.219.238.113")==0 ){
		   lnet=libnet_init(LIBNET_RAW4,dev, errbuf_lnet);
		   if(size_tcp>TCP_HEADER_SIZE){
		    option=(char *)packet+54;
		    option_s=size_tcp-TCP_HEADER_SIZE;
	        printf("options----%d \n",option_s);
		if(libnet_build_tcp_options((u_int8_t *)option,option_s,lnet,0)==-1){
			    printf("fail-1 ------");
			    libnet_destroy(lnet);
                exit(EXIT_FAILURE);
			}
		}
		       u_int32_t sip;
               sip=libnet_get_ipaddr4(lnet);
		       if(size_payload==0){
			   if (t=libnet_build_tcp(ntohs(tcp1->th_sport), ntohs(tcp1->th_dport),seq,
		       ntohl(tcp1->th_ack),tcp1->th_flags,win,0,ntohs(tcp1->th_urp),size_tcp,NULL,0 ,lnet,0)==-1)
           {
               printf("fail-1 ------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
           }  
           libnet_toggle_checksum(lnet,t,LIBNET_ON);     
        if(t=libnet_build_ipv4(size_ip+size_tcp,
        ip1->ip_tos,
        ip1->ip_id,0,
        ip1->ip_ttl,ip1->ip_p,0,sip,ip1->ip_dst.s_addr,NULL,0,lnet,0)==-1){  
               printf("fail-1 ------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
               }
              libnet_toggle_checksum(lnet,t,LIBNET_ON);     
              int c=libnet_write(lnet);
              libnet_destroy(lnet);
		      printf("after send %d:--",c);
          } 
          
    ///////////////////////////////////////////////////////////////////      
    //////////////////////////////////////////////////////////////////      
          
		  if(size_payload > 0) {
		  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		 // print_payload(payload, size_payload);
		  if (t=libnet_build_tcp(ntohs(tcp1->th_sport), ntohs(tcp1->th_dport),seq,
		  ntohl(tcp1->th_ack),tcp1->th_flags,win,0,tcp1->th_urp,size_tcp+size_payload,(u_int8_t *)payload,size_payload ,lnet,0)==-1)
        {
              
               printf("fail-1 ------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
        }
        libnet_toggle_checksum(lnet,t,LIBNET_ON);     
        if(t=libnet_build_ipv4(size_ip+size_tcp+size_payload,
        ip1->ip_tos,
        ip1->ip_id,0,
        ip1->ip_ttl,ip1->ip_p,0,sip,ip1->ip_dst.s_addr,NULL,0,lnet,0)==-1) {
              
               printf("fail--2 ------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
        }
        libnet_toggle_checksum(lnet,t,LIBNET_ON);     
        int c=libnet_write(lnet);
		printf("after send to server %d:--",c);
		}
		libnet_destroy(lnet);
	}
if(strcmp(inet_ntoa(ip1->ip_src),"217.219.238.113")==0 && 
          strcmp(inet_ntoa(ip1->ip_dst),"192.168.0.112")==0 ){
	           lnet=libnet_init(LIBNET_LINK,dev, errbuf_lnet);
	           if(size_tcp>TCP_HEADER_SIZE){
		       option=(char *)packet+54;
		       option_s=size_tcp-TCP_HEADER_SIZE;
	           printf("options from server---%d \n",option_s);
		if(libnet_build_tcp_options((u_int8_t *)option,option_s,lnet,0)==-1){
			    printf("fail-1 ------");
			    libnet_destroy(lnet);
                exit(EXIT_FAILURE);
			}
		}
		
		      struct in_addr dip;
		      dip.s_addr=inet_addr("192.168.0.223");
		       if(size_payload==0){
			   if (t=libnet_build_tcp(ntohs(tcp1->th_sport), ntohs(tcp1->th_dport),seq,
		       ntohl(tcp1->th_ack),tcp1->th_flags,win,0,ntohs(tcp1->th_urp),size_tcp,NULL,0 ,lnet,0)==-1)
        {
               printf("fail-1 ------");
               exit(EXIT_FAILURE);
               libnet_destroy(lnet);
        }    
            libnet_toggle_checksum(lnet,t,LIBNET_ON);     
           
        if(t=libnet_build_ipv4(size_ip+size_tcp,
        ip1->ip_tos,
        ip1->ip_id,0,
        ip1->ip_ttl,ip1->ip_p,0,ip1->ip_src.s_addr,dip.s_addr,NULL,0,lnet,0)==-1){  
               printf("fail-2 ------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
               }
               char *ether_dst="f0:79:59:5f:d2:fe";
               printf("ma inja hastim .........");
               int k;
               ether_dst=libnet_hex_aton(ether_dst,&k);
               if(t=libnet_autobuild_ethernet(ether_dst,ETHERTYPE_IP,lnet)==-1)
               {
			   printf("fail-3 ------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
               }
               //free(ether_dst);
            libnet_toggle_checksum(lnet,t,LIBNET_ON);                   
        int c=libnet_write(lnet);
		printf("after send to client %d:--",c);
}
		if(size_payload >0) {
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	   // print_payload(payload, size_payload);

		if (libnet_build_tcp(ntohs(tcp1->th_sport), ntohs(tcp1->th_dport),seq,
		  ntohl(tcp1->th_ack),tcp1->th_flags,win,tcp1->th_sum,tcp1->th_urp,size_tcp+size_payload,(u_int8_t *)payload,size_payload ,lnet,0)==-1)
        {
               printf("fail-1 ------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
        }
        if(libnet_build_ipv4(size_ip+size_tcp+size_payload,
        ip1->ip_tos,
        ip1->ip_id,0,
        ip1->ip_ttl,ip1->ip_p,ip1->ip_sum,ip1->ip_src.s_addr,dip.s_addr,NULL,0,lnet,0)==-1) {
              
               printf("fail--2 ------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
        }
        int c=libnet_write(lnet);
		printf("after send to client %d:--",c);}
		libnet_destroy(lnet);
	}

return;
}

void enable_ip_forward(){
	  FILE *fd;
   
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "r");
   //ON_ERROR(fd, NULL, "failed to open /proc/sys/net/ipv4/ip_forward");

   fscanf(fd, "%c", &saved_status);
   fclose(fd);

   //DEBUG_MSG("disable_ip_forward: old value = %c", saved_status);
 
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "w");
   //ON_ERROR(fd, NULL, "failed to open /proc/sys/net/ipv4/ip_forward");
   
   fprintf(fd, "1");
   fclose(fd);
   }
   
   void disable_ip_forward()
{
	  FILE *fd;
   
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "r");
   //ON_ERROR(fd, NULL, "failed to open /proc/sys/net/ipv4/ip_forward");

   fscanf(fd, "%c", &saved_status);
   fclose(fd);

   //DEBUG_MSG("disable_ip_forward: old value = %c", saved_status);
 
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "w");
   //ON_ERROR(fd, NULL, "failed to open /proc/sys/net/ipv4/ip_forward");
   
   fprintf(fd, "0");
   fclose(fd);
   }
int main(int argc, char **argv)
{

	char filter_exp[] = "(tcp port 443 and src 192.168.0.223 and dst 217.219.238.113) or  (tcp port 443 and src 217.219.238.113 and dst 192.168.0.112)  ";
	struct bpf_program fp;			
	bpf_u_int32 mask;
    libnet_t *lnets;			
	bpf_u_int32 net;			
	int num_packets = 20000;			
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		//print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}
		
 disable_ip_forward();
	printf("Device: %s\n", dev);
	printf("Number of packets : %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);
	handle = pcap_open_live(dev, SNAP_LEN, 1, 20000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
				
		pcap_loop(handle, -1, got_packet,NULL);

	pcap_freecode(&fp);
	pcap_close(handle);
	printf("\nCapture complete.\n");

return 0;
}

