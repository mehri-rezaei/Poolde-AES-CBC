

	
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


#define SIZE_ETHERNET 14
#define TCP_HEADER_SIZE 20
#define SNAP_LEN 1518

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
	pcap_t *handle;
	libnet_t *lnet;	
	char *dev = NULL;			
	char errbuf[PCAP_ERRBUF_SIZE];
	char errbuf_lnet[LIBNET_ERRBUF_SIZE];	

void got_packet(u_char *args, const struct pcap_pkthdr *header,  u_char *packet);
void disable_ip_forward();
void enable_ip_forward();

void got_packet(u_char *args, const struct pcap_pkthdr *header, u_char *packet)
{

	static int count = 1; 
    struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	struct sniff_tcp *tcp1; 
	libnet_t *lnet;
	int size_ip;
	int size_tcp;
	int size_payload;
	u_char *option;
	int option_s;
	u_int32_t seq, win;
    u_char *payload;  
    u_int32_t src_ip;
			
	ip = (struct libnet_ipv4_hdr *)(packet+SIZE_ETHERNET);
     size_ip = IP_HL(ip)*4;
  // if( (strcmp(inet_ntoa(ip->ip_src),"192.168.0.223")==0 && 
          //strcmp(inet_ntoa(ip->ip_dst),"10.0.0.10")==0) ||(strcmp(inet_ntoa(ip->ip_src),"192.168.0.223")==0 && 
         // strcmp(inet_ntoa(ip->ip_dst),"77.104.106.2")==0)){
			//  enable_ip_forward();
			 // }
			  
		
				  //disable_ip_forward();
	tcp = (struct libnet_tcp_hdr *)(packet +SIZE_ETHERNET+ size_ip);
	tcp1 = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
     size_tcp = TH_OFF(tcp1)*4;
	 seq = ntohl(tcp->th_seq);
	 win = ntohs(tcp->th_win);     
	
	
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
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	
	printf("   Payload (%d bytes):\n", size_payload);
	
//recieve packet from client and send to  server with ip(217.219.238.113).
	  if(strcmp(inet_ntoa(ip->ip_src),"192.168.0.223")==0 &&
	 strcmp(inet_ntoa(ip->ip_dst),"217.219.238.113")==0 )
	  {

		   lnet=libnet_init(LIBNET_RAW4,dev, errbuf_lnet);
		   if(size_tcp>TCP_HEADER_SIZE)
		   {
		    option=(char *)packet+54;
		    option_s=size_tcp-TCP_HEADER_SIZE;

	    	if(libnet_build_tcp_options((u_int8_t *)option,option_s,lnet,0)==-1)
		    {
			    printf("fail-1 ------");
			    libnet_destroy(lnet);
                exit(EXIT_FAILURE);
			}
		}
		       
          src_ip=libnet_get_ipaddr4(lnet);
		      
		
		
		//
		if(size_payload>2){
				if(*(payload)==0x17 && *(payload++)==0x03 && *(payload++)==0x00){
							 // *(payload+size_payload-1)=*(payload++);
							 printf("data");
						 }

}
		//
		  
		  if (libnet_build_tcp(ntohs(tcp->th_sport),
		   ntohs(tcp->th_dport),
		   seq,
		  ntohl(tcp->th_ack),
		  tcp->th_flags,
		  win,
		  0,
		  ntohs(tcp->th_urp),
		  size_tcp+size_payload,
		  (u_int8_t *)payload,
		  size_payload,
		  lnet,0)==-1)
        {
               printf("fail-1  tcp client------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
        }
        if(libnet_build_ipv4(size_ip+size_tcp+size_payload,
        ip->ip_tos,
        ip->ip_id,
        0,
        ip->ip_ttl,
        ip->ip_p,
        0,//checksum 
        src_ip,
        ip->ip_dst.s_addr,
        NULL,
        0,
        lnet,0)==-1) {
              
               printf("fail--2 ------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
        }
        libnet_write(lnet);
        libnet_destroy(lnet);

		}
	
//recieve packet from server and send to client

    if(strcmp(inet_ntoa(ip->ip_src),"217.219.238.113")==0 && 
          strcmp(inet_ntoa(ip->ip_dst),"192.168.0.112")==0){
			  
			  //disable_ip_forward();
			  
	           lnet=libnet_init(LIBNET_LINK,dev, errbuf_lnet);
	           
	           if(size_tcp > TCP_HEADER_SIZE)
	           {
		       option=(char *)packet+54;
		       option_s=size_tcp-TCP_HEADER_SIZE;
		       
		       if(libnet_build_tcp_options((u_int8_t *)option,option_s,lnet,0)==-1)
		       {
			    printf("fail-1 ------");
			    libnet_destroy(lnet);
                exit(EXIT_FAILURE);
			}
		}
		
		      struct in_addr dst_ip;
		      dst_ip.s_addr=inet_addr("192.168.0.223");
              char *ether_dst="f0:79:59:5f:d2:fe";
               int k;
               ether_dst=libnet_hex_aton(ether_dst,&k);
               		  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);


		if (libnet_build_tcp(ntohs(tcp->th_sport),
		 ntohs(tcp->th_dport),
		  seq,
		  ntohl(tcp->th_ack),
		  tcp->th_flags,
		  win,
		  0, //checksum
		  ntohs(tcp->th_urp),
		  size_tcp+size_payload,
		  (u_int8_t *)payload,
		  size_payload ,
		  lnet,0)==-1)
        {
               printf("fail-1  tcp------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
        }
        if(libnet_build_ipv4(size_ip+size_tcp+size_payload,
        ip->ip_tos,
        ip->ip_id,
        0,
        ip->ip_ttl,
        ip->ip_p,
        0, //checksum
        ip->ip_src.s_addr,
        dst_ip.s_addr,
        NULL,
        0,
        lnet,0)==-1) 
        {
               printf("fail--2  ip------");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
        }
          if(libnet_autobuild_ethernet(ether_dst,ETHERTYPE_IP,lnet)==-1)
               {
			   printf("fail-3  ethernt-----");
               libnet_destroy(lnet);
               exit(EXIT_FAILURE);
               }
        libnet_write(lnet);
        libnet_destroy(lnet);
	}

	return;
}
      void enable_ip_forward()
{
	 FILE *fd;
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "r");
   fscanf(fd, "%c", &saved_status);
   fclose(fd); 
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "w");   
   fprintf(fd, "1");
   fclose(fd);
   }

   void disable_ip_forward()
{
	 FILE *fd;
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "r");
   fscanf(fd, "%c", &saved_status);
   fclose(fd); 
   fd = fopen("/proc/sys/net/ipv4/ip_forward", "w");   
   fprintf(fd, "0");
   fclose(fd);
   }
int main(int argc, char **argv)
{

	char filter_exp[] = "(tcp port 443 and src 192.168.0.223 and dst 217.219.238.113) or  (tcp port 443 and src 217.219.238.113 and dst 192.168.0.112)";
	//or (src 192.168.0.223 and dst 10.0.0.10) or (src 192.168.0.223 and dst 77.104.106.2)  ";
	struct bpf_program fp;			
	bpf_u_int32 mask;
	bpf_u_int32 net;			
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
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

