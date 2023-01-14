#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};


/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
};

unsigned short in_cksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry-outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}


/*************************************************************
  Given an IP packet, send it out using a raw socket. 
**************************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, 
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}



/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/
int spoofICMP(char *dest) {

   char buffer[1500];
   memset(buffer, 0, 1500);
   

   /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
   struct icmpheader *icmp = (struct icmpheader *) 
                             (buffer + sizeof(struct ipheader));
   icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

   // Calculate the checksum for integrity
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = in_cksum((unsigned short *)icmp, 
                                 sizeof(struct icmpheader));

   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
   struct ipheader *ip = (struct ipheader *) buffer;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
   ip->iph_destip.s_addr = inet_addr(dest);
   ip->iph_protocol = IPPROTO_ICMP; 
   ip->iph_len = htons(sizeof(struct ipheader) + 
                       sizeof(struct icmpheader));


    

   /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
   send_raw_ip_packet (ip);

   return 0;
}










/******************************************************************
  Spoof a UDP packet using an arbitrary source IP Address and port 
*******************************************************************/
int spoofUDP(char *dest, int port) {
   char buffer[1500];

   memset(buffer, 0, 1500);
   struct ipheader *ip = (struct ipheader *) buffer;
   struct udpheader *udp = (struct udpheader *) (buffer +
                                          sizeof(struct ipheader));

   /*********************************************************
      Step 1: Fill in the UDP data field.
    ********************************************************/
   char *data = buffer + sizeof(struct ipheader) + 
                         sizeof(struct udpheader);
   const char *msg = "Hello Server!\n";
   int data_len = strlen(msg);
   strncpy (data, msg, data_len);

   /*********************************************************
      Step 2: Fill in the UDP header.
    ********************************************************/
   udp->udp_sport = htons(12345);
   udp->udp_dport = htons(port);
   udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
   udp->udp_sum =  0; /* Many OSes ignore this field, so we do not 
                         calculate it. */

   /*********************************************************
      Step 3: Fill in the IP header.
    ********************************************************/

   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 21;
   ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
   ip->iph_destip.s_addr = inet_addr(dest);
   ip->iph_protocol = IPPROTO_UDP; 
   ip->iph_len = htons(sizeof(struct ipheader) + 
                       sizeof(struct icmpheader) + data_len);


   /*********************************************************
      Step 4: Finally, send the spoofed packet
    ********************************************************/
   send_raw_ip_packet (ip);

   return 0;
}



int main(){

  int choice=-1;
  while(choice!=0){

    printf("Enter (1) to spoof ICMP packet\nEnter (2) to spoof UDP packet\nEnter (0) to exit\n");
    scanf("%d",&choice);

    
    if(choice==1){
      char dest[16];
      printf("Enter ip to send spoofed packet: ");
      scanf("%s",dest);
      int spoofer=spoofICMP(dest);
      if(spoofer!=0){
        perror("(-) Spoofing failed.\n");
        exit(EXIT_FAILURE);
      }else{
        printf("(+) Spoofed successfully.\n");
      }
    }

    else if(choice==2){
      char dest[16];
      int port=0;
      printf("Enter ip to send spoofed packet: ");
      scanf("%s",dest);
      printf("Enter port to send spoofed packet: ");
      scanf("\n %d",&port);
      int spoofer=spoofUDP(dest,port);
      if(spoofer!=0){
        perror("(-) Spoofing failed.\n");
        exit(EXIT_FAILURE);
      }else{ 
        printf("(+) Spoofed successfully.\n");
        
      }
    }
    else{
      perror("(-) Invalid input. \n");
      exit(EXIT_FAILURE);
    }
    printf("\nEnter (1) to spoof ICMP packet\nEnter (2) to spoof UDP packet\nEnter (0) to exit\n");
    scanf("%d",&choice);
  }
  
  return 0;
}