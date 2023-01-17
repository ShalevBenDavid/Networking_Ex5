// Created by Shalev Ben David and Ron Shuster.

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <arpa/inet.h>

int seq = 0;

unsigned short in_cksum(unsigned short *, int);
int spoofICMP(char *);
int spoofUDP(char *, int);
int spoofTCP(char *, int);

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

/********************************************************
  User Choice: 0 To Exit, 1 To Spoof ICMP, 2 To Spoof UDP
*********************************************************/
int main() {
    int choice = 0;
    printf("Enter (1) to spoof ICMP packet\nEnter (2) to spoof UDP packet\nEnter (3) to spoof TCP packet\n"
           "Enter (0) to exit\n");
    scanf("%d", &choice);
    while(choice != 0) {
        if(choice == 1) { // ICMP
            char dest[16];
            printf("Enter ip to send spoofed packet: ");
            scanf("%s",dest);
            spoofICMP(dest);
            printf("(+) Spoofed ICMP packet successfully.\n");
            }

        else if (choice == 2) { // UDP
            char dest[16];
            int port = 0;
            printf("Enter ip to send spoofed packet: ");
            scanf("%s", dest);
            printf("Enter port to send spoofed packet: ");
            scanf("\n %d", &port);
            spoofUDP(dest,port);
            printf("(+) Spoofed UDP packet successfully.\n");
        }

        else if (choice == 3) { // TCP
            char dest[16];
            int port = 0;
            printf("Enter ip to send spoofed packet: ");
            scanf("%s", dest);
            printf("Enter port to send spoofed packet: ");
            scanf("\n %d", &port);
            spoofTCP(dest,port);
            printf("(+) Spoofed TCP packet successfully.\n");
        }

        else {
            perror("(-) Invalid input. Try again. \n");
        }
        printf("Enter (1) to spoof ICMP packet\nEnter (2) to spoof UDP packet\nEnter (3) to spoof TCP packet\n"
               "Enter (0) to exit\n");
        scanf("%d", &choice);
    }
    return 0;
}

/***************************************************
  Given an IP packet, send it out using a raw socket.
****************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip -> iph_destip;

    // Step 4: Send the packet out.
    if (sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) == -1) {
        perror("(-) Error in sending spoofed packet.\n");
        exit(EXIT_FAILURE);
    }
    else {
        printf("(+) Created and sent the spoofed packet.\n");
    }

    // Step 5: Close the socket.
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
   struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
   icmp -> icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

   // Calculate the checksum for integrity
   icmp -> icmp_chksum = 0;
   icmp -> icmp_chksum = in_cksum((unsigned short *)icmp,sizeof(struct icmpheader));

   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
   struct ipheader *ip = (struct ipheader *) buffer;
   ip -> iph_ver = 4;
   ip -> iph_ihl = 5;
   ip -> iph_ttl = 20;
   ip -> iph_sourceip.s_addr = inet_addr("1.2.3.4");
   ip -> iph_destip.s_addr = inet_addr(dest);
   ip -> iph_protocol = IPPROTO_ICMP;
   ip -> iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

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
   struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));

   /*********************************************************
      Step 1: Fill in the UDP data field.
    ********************************************************/
   char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
   const char *msg = "This is a fake ping!\n";
   int data_len = strlen(msg);
   strncpy (data, msg, data_len);

   /*********************************************************
      Step 2: Fill in the UDP header.
    ********************************************************/
   udp -> udp_sport = htons(12345);
   udp -> udp_dport = htons(port);
   udp -> udp_ulen = htons(sizeof(struct udpheader) + data_len);
   udp -> udp_sum =  0; /* Many OSes ignore this field, so we do not
                         calculate it. */

   /*********************************************************
      Step 3: Fill in the IP header.
    ********************************************************/
   ip -> iph_ver = 4;
   ip -> iph_ihl = 5;
   ip -> iph_ttl = 21;
   ip -> iph_sourceip.s_addr = inet_addr("1.2.3.4"); // Spoofed source ip address.
   ip -> iph_destip.s_addr = inet_addr(dest); // Same destination ip.
   ip -> iph_protocol = IPPROTO_UDP;
   ip -> iph_len = htons(sizeof(struct ipheader) +sizeof(struct icmpheader) + data_len);

   /*********************************************************
      Step 4: Finally, send the spoofed packet
    ********************************************************/
   send_raw_ip_packet (ip);

   return 0;
}

/******************************************************************
  Spoof a TCP packet using an arbitrary source IP Address and port
*******************************************************************/
int spoofTCP(char *dest, int port) {
    char buffer[1500];

    memset(buffer, 0, 1500);
    struct ipheader *ip = (struct ipheader *) buffer;
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct ipheader));

    /*********************************************************
       Step 1: Fill in the TCP data field.
     ********************************************************/
    char *data = buffer + sizeof(struct ipheader) + sizeof(struct tcphdr);
    const char *msg = "This is a fake ping!\n";
    int data_len = strlen(msg);
    strncpy (data, msg, data_len);

    /*********************************************************
       Step 2: Fill in the TCP header.
     ********************************************************/
    tcp -> th_sport = htons(12345);
    tcp -> th_dport = htons(port);
    tcp -> th_ack = 1;
    tcp -> th_seq = seq++;
    tcp -> th_flags = 0x08; // Push type;
    tcp -> th_off = 5; // The offset is 5 meaning our tcp length is 28.
    tcp -> th_win = htons(1000);
    tcp -> th_sum = in_cksum((unsigned short *)tcp,sizeof(struct tcphdr) + data_len);

    /*********************************************************
       Step 3: Fill in the IP header.
     ********************************************************/
    ip -> iph_ver = 4;
    ip -> iph_ihl = 5;
    ip -> iph_ttl = 21;
    ip -> iph_sourceip.s_addr = inet_addr("1.2.3.4"); // Spoofed source ip address.
    ip -> iph_destip.s_addr = inet_addr(dest); // Same destination ip.
    ip -> iph_protocol = IPPROTO_TCP;
    ip -> iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcphdr) + data_len);

    /*********************************************************
       Step 4: Finally, send the spoofed packet
     ********************************************************/
    send_raw_ip_packet (ip);

    return 0;
}

/*****************
   Checksum Method
 *****************/
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