/* 
 * File:   source.c
 * Author: Shivanshu Misra
 *
 * Created on 13 October, 2013, 3:02 AM
 */

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#define PCAP_FILE "./pcap_file"
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6

/* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };
    
/* IP header */
    struct sniff_ip {
        u_char ip_vhl;      /* version << 4 | header length >> 2 */
        u_char ip_tos;      /* type of service */
        u_short ip_len;     /* total length */
        u_short ip_id;      /* identification */
        u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
        u_char ip_ttl;      /* time to live */
        u_char ip_p;        /* protocol */
        u_short ip_sum;     /* checksum */
        struct in_addr ip_src;
        struct in_addr ip_dst; /* source and dest address */
    };
 #define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
 #define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* TCP header */
    struct sniff_tcp {
        u_short th_sport;   /* source port */
        u_short th_dport;   /* destination port */
        u_int32_t th_seq;       /* sequence number */
        u_int32_t th_ack;       /* acknowledgement number */

        u_char th_offx2;    /* data offset*/
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR) 
      u_short th_win;     /* window */
        u_short th_sum;     /* checksum */
        u_short th_urp;     /* urgent pointer */
};

	FILE *outFile;
//Function to display payload extracted from the input packet
void  display_payload(const u_char *payload, int len);
//Function to extract ASCII values in payload data
void display_ascii_line(const u_char *payload, int len, int offset);


void display_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
   const u_char *ch = payload;
    for(i =0; i<len; i++)
    {
        if (isprint(*ch)){
			printf("%c", *ch);
			fprintf(outFile, "%c", *ch);
	}	
	else
		{
			printf(".");
			fprintf(outFile,".");
		}			
ch++;
    }
    printf("\n");
    return;
}

void display_payload(const u_char *payload, int len)
{
    int len_rem = len;
	int line_width = 16;		
	int line_len;
	int offset = 0;				
	const u_char *ch = payload;
        
        if(len <= 0)
            return;
        
        if(len <= line_width){
            display_ascii_line(ch, len, offset);
            return;
        }
        
        	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
                display_ascii_line(ch, line_len, offset);
                len_rem = len_rem - line_len;
                ch = ch + line_len;
                offset = offset + line_width;
                
                if (len_rem <= line_width) {
                    display_ascii_line(ch, len_rem, offset);
                    break;
                }
}
        return;
}
int main(int argc, char **argv)
	{
            char *device;       //Interface name
            char *netaddr;       
            char *netmask;      
	          
            int flag;           
            char errbuf[PCAP_ERRBUF_SIZE];
            bpf_u_int32 mask_r;         //Subnetwork Mask
            bpf_u_int32 ip_r;           //Network Address
            struct in_addr addresses;
            
	    char prestr[80];   	
            pcap_dumper_t *pd;       /* pointer to the dump file */
            pcap_t* sniff;
             
	int compile;
            
	int filter;            
            const u_char *packet;             //changed from char
                 
            const u_char *payload;  
            struct bpf_program cp;      /* hold compiled program     */
            
            char file_input[80];
            printf("\n Enter the input file : ");
            scanf("%s",file_input);
            
             char file_out[80];
                 printf("\n Enter the output file : ");
            scanf("%s",file_out);
            
            
            //Check the Interface available
            device  = pcap_lookupdev(errbuf); //returns the interface name
            if(device == NULL)
            {
                printf("No device found%s\n", errbuf);
                exit(1);
            }
            else
            {
                printf("Interface: %s\n", device); 
	     //Print the interface name
             }
             
            //Open the interface to read traffic 
            /* amount of data per packet = 80 */
            /* promiscuous mode = 0*/
            /* timeout, in milliseconds = 1000*/
            sniff = pcap_open_live(device,80,0,1000,errbuf);    //BUFSIZ  replaced by snaplen = 80
            if(sniff == NULL)
            {
                printf("Error sniffing the Interface: %s: %s",device,errbuf);
                exit(2);                        
            }        
            
            flag = pcap_lookupnet(device,&ip_r,&mask_r,errbuf); 
        	//returns network address and network mask
              if(flag == -1){
                printf("pcap_lookupnet Error: %s\n", errbuf);
                exit(3);
            }
            addresses.s_addr = ip_r;
            netaddr = inet_ntoa(addresses);  
        
	    printf("IP Address of Inteface: %s\n", netaddr);
    
            addresses.s_addr =  mask_r;
            netmask = inet_ntoa(addresses);
            
            printf("Network Mask of Inteface: %s\n", netmask);
                 
            /* passed to pcap_compile to do optimization = 1*/
            
            compile = pcap_compile(sniff, &cp, argv[1], 1, mask_r);
            if(compile == -1){
                fprintf(stderr,"Error calling pcap_compile\n"); 
                exit(3);
            }
            
            // Setting the filter 
            filter  = pcap_setfilter(sniff, &cp);
           
                        if(filter == -1)	
	    {
                fprintf(stderr,"Error setting filter\n");
                exit(4);
            }
            
               printf("\n\n"); 
        
            //char file_input[80] = "/home/shivanshu/from_host/test3.pcap";
            //FILE *inFile = fopen(file_input, "r");
            pcap_t * pcap = pcap_open_offline(file_input, errbuf);
            
             //The header that pcap gives us
                struct pcap_pkthdr *header;
                int packetCount = 0, i;    
              
               
                
            outFile = fopen(file_out, "w");
            
            //tcp info
        const struct sniff_ethernet *ethernet; /* The ethernet header */
        const struct sniff_ip *ip; /* The IP header */
        const struct sniff_tcp *tcp; /* The TCP header */
                u_int size_ip;
                u_int size_tcp;
                const u_char *Data;
       while(pcap_next_ex(pcap, &header, &packet) >= 0)
       {
           //Display Packet Number
           printf("Packet Count# %i\n :", ++packetCount);
           fprintf(outFile, "\nPacket Count# %i\n", packetCount);
           
           //Display size of a packet
           printf("Packet size: %d bytes\n", header->len);
           fprintf(outFile,"Packet size: %d bytes\n", header->len);
           
           //Display warning if size of packet captured is different
           if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
       
           //Extract Timestamp and display
           printf("Timestamp: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);
            fprintf(outFile,"Timestamp: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);
       
             ethernet = (struct sniff_ethernet*)(packet);
                 ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
                        size_ip = IP_HL(ip)*4;
                        if (size_ip < 20) 
                {
                 printf("Invalid IP header length: %u bytes\n", size_ip);
                 //return;
                }

                 tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
                 size_tcp = TH_OFF(tcp)*4;
                  printf("Source Port: %d Destination Port: %d \n", tcp->th_sport, tcp->th_dport);
                   fprintf(outFile,"Source Port: %d Destination Port: %d \n", tcp->th_sport, tcp->th_dport);
                   
                   printf("Source Address: %s Destination Address: %s \n",  inet_ntoa(ip->ip_src),  inet_ntoa(ip->ip_dst));
                   fprintf(outFile,"Source Address: %s Destination Address: %s \n",  inet_ntoa(ip->ip_src),  inet_ntoa(ip->ip_dst));
                    
                    printf("Sequence Number: %u Acknowledgment Number: %u \n", (unsigned int)tcp-> th_seq, (unsigned int)tcp->th_ack);
                    fprintf(outFile,"Sequence Number: %u Acknowledgment Number: %u \n", (unsigned int)tcp-> th_seq, (unsigned int)tcp->th_ack); 
                    
                    printf("\n");
                    fprintf(outFile,"\n");
                    
                    //Calculating tcp payload offset
                       /* Packet payload */
                    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
                    
                    //Calculating tcp payload size
                  int  size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
                  //Print Payload data
                  if(size_payload > 0)
                  {
                      printf("Payload Size %d bytes:\n", size_payload);
                      fprintf(outFile, "Payload Size %d bytes:\n", size_payload);	  
		      display_payload(payload, size_payload);
                  }
                    
       } 
             //Extract payload and display
            
             while(pcap_next_ex(pcap, &header, &Data) >= 0)
             {
             for(u_int i = 0; i <header -> caplen; i++)
             {
                 if((i%16) == 0){
                     printf("\n");
                     fprintf(outFile, "\n");
                 }
                 printf("%.2 x", Data[i]);
                 fprintf(outFile, "%.2 x", Data[i]);
                 //print each octet as hex (x)
             }    
             }             
                fclose(outFile);
		        return(0);
            
       }

