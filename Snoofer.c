// Created by Shalev Ben David and Ron Shuster.

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <strings.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#define PACKET_LEN 1500

struct ipheader;
unsigned short in_cksum(unsigned short *, int );
void spoof_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void send_raw_ip_packet(struct ipheader*);

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

/********************************
 * Packet Capturing Using Sniffer
 ********************************/
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp"; // Filter icmp: sniff only icmp packets.
    bpf_u_int32 net = 0;

    // Step 1: Open live pcap session on NIC.
    printf("Opening device for sniffing...\n");
    handle = pcap_open_live("enp0s1", PACKET_LEN, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    printf("Setting the filter for ICMP packets only.\n");
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, spoof_packet, NULL);

    // Step 4: Close the handle
    pcap_close(handle);

    return 0;
};

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
    int bytes = sendto(sock, ip, ntohs(ip -> iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    printf("bytes %d\n", bytes);
    // Step 5: Close the socket.
    close(sock);
}

void spoof_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("header len: %d\n", header->len);
    unsigned char* spoofed = (unsigned char*) malloc (header -> len - sizeof(struct ethhdr));
    if (spoofed == NULL) {
        printf("Allocation failed!\n");
        return;
    }

    printf("\n-------spoofed--------\n\n");
    struct ipheader *ip_spoofed = (struct ipheader *) spoofed; // Pointer to ip header of spoofed packet.
    struct ipheader *ip_original = (struct ipheader *) (packet + sizeof(struct ethhdr)); // Pointer to ip header of original// packet.
    struct icmpheader *icmp_spoofed = (struct icmpheader *) (spoofed + sizeof(struct ipheader));
    struct icmpheader *icmp_original = (struct icmpheader *) (packet + sizeof(struct ipheader) + sizeof(struct ethhdr));

    memcpy(ip_spoofed, ip_original, header -> len - sizeof(struct ether_addr));
    if (icmp_original -> icmp_type == 8) {
        /*********************************************************
           Step 1: Fill in the ICMP header.
         ********************************************************/
        icmp_spoofed -> icmp_type = 0; // Spoofing an echo response.
        // Calculate the checksum for integrity
        icmp_spoofed -> icmp_chksum = 0;
        icmp_spoofed -> icmp_chksum = in_cksum((unsigned short *) icmp_spoofed, sizeof(struct icmpheader));

        /*********************************************************
           Step 2: Fill in the IP header.
         ********************************************************/
        ip_spoofed -> iph_ver = 4;
        ip_spoofed -> iph_ihl = ip_original -> iph_ihl;
        ip_spoofed->iph_ttl = ip_original -> iph_ttl;
        ip_spoofed->iph_sourceip.s_addr = inet_addr("1.2.3.4");
        ip_spoofed->iph_destip.s_addr = ip_original -> iph_sourceip.s_addr;
        ip_spoofed->iph_protocol = ip_original -> iph_protocol;
        ip_spoofed->iph_len = ip_original -> iph_len;

        /*********************************************************
           Step 3: Finally, send the spoofed packet
         ********************************************************/
        send_raw_ip_packet(ip_spoofed);
    }
    free(spoofed);
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