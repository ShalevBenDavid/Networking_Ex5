// Created by Shalev Ben David on 12/01/2023.

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <arpa/inet.h>

#define PACKET_LEN 512

char data[PACKET_LEN]; // The buffer to hold the packet.

int sniffer();
void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

/* Ethernet header */
struct eth_header {
    u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ip_header {
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

struct app_header {
    uint32_t unixtime;
    uint16_t length;
    uint16_t reserved:3,c_flag:1,s_flag:1,t_flag:1,status:10;
    uint16_t cache;
    uint16_t padding;
};

struct tcp_header {
    unsigned short source_port;  // source port
    unsigned short dest_port;    // destination port
    unsigned int   sequence;     // sequence number - 32 bits
    unsigned int   acknowledge;  // acknowledgement number - 32 bits

    unsigned char  ns   :1;          //Nonce Sum Flag Added in RFC 3540.
    unsigned char  reserved_part1:3; //according to rfc
    unsigned char  data_offset:4;    //number of dwords in the TCP header.

    unsigned char  fin  :1;      //Finish Flag
    unsigned char  syn  :1;      //Synchronise Flag
    unsigned char  rst  :1;      //Reset Flag
    unsigned char  psh  :1;      //Push Flag
    unsigned char  ack  :1;      //Acknowledgement Flag
    unsigned char  urg  :1;      //Urgent Flag

    unsigned char  ecn  :1;      //ECN-Echo Flag
    unsigned char  cwr  :1;      //Congestion Window Reduced Flag

    unsigned short window;          // window
    unsigned short checksum;        // checksum
    unsigned short urgent_pointer;  // urgent pointer
};

int main()
{
    // ------------------------------- Creating RAW Sockets -------------------------------
    struct sockaddr saddr;
    struct packet_mreq mr;

    // Create the raw socket and allow him to capture all types of packets.
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // Turn on the promiscuous mode.
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    // Getting captured packets
    while (1) {
        ssize_t data_size = recvfrom(sock, data, PACKET_LEN, 0, &saddr, (socklen_t*)sizeof(saddr));
        if(data_size) {
            sniffer();
            printf("Got one packet\n");
        }
    }
    close(sock);
    return 0;
}

/***********************************
 * Packet Capturing using raw socket
 ***********************************/
int sniffer() {
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;
        char filter_exp[] = "ip proto icmp";
        bpf_u_int32 net;

        // Step 1: Open live pcap session on NIC with name eth3
        handle = pcap_open_live("eth3", BUFSIZ, 1, 1000, errbuf);

        // Step 2: Compile filter_exp into BPF psuedo-code
        pcap_compile(handle, &fp, filter_exp, 0, net);
        pcap_setfilter(handle, &fp);

        // Step 3: Capture packets
        void (*pcap_handler) (u_char *, const struct pcap_pkthdr *, const u_char *);
        pcap_handler = got_packet;
        pcap_loop(handle, -1, pcap_handler, NULL);

        pcap_close(handle);   //Close the handle
        return 0;
}


/***********************************
 * Packet Handeling
 ***********************************/

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // Creating pointer to the ethernet header.
    struct eth_header *eth = (struct eth_header *) packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        // Creating pointer to the ip header.
        struct ip_header *ip = (struct ip_header *) (packet + sizeof(struct eth_header));
        // Creating pointer to the tcp header.
        struct tcp_header *tcp = (struct tcp_header *) ((u_char *) ip + sizeof(struct ip_header));
        // Creating pointer to the app header.
        struct app_header *app = (struct app_header *) ((packet + (tcp->data_offset * 4)));
        FILE *file_pointer;
        file_pointer = fopen("325092781_318848413", "a");
        if (file_pointer == NULL) {
            printf("Could not open file");
        }
        char hex_data[2 * strlen(data) + 1];
        for (int i = 0; i < strlen(data); i++) {
            sprintf(hex_data + i * 2, "%02x", data[i]);
        }
        fprintf(file_pointer, "source_ip: %s, dest_ip: %s, source_port: %d, dest_port: &d, "
                              "timestamp: %u, total_length: %u, cache_flag: %u, steps_flag: %u, "
                              "type_flag: %u, status_code: %u, cache_control: %u, data: %s\n\n",
                inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip), ntohs(tcp->source_port),
                ntohs(tcp->dest_port), app->unixtime, app->length, app->c_flag, app->s_flag,
                app->t_flag, app->cache, hex_data);
    }
}