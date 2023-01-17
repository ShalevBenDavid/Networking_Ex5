// Created by Shalev Ben David and Ron Shuster.

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <strings.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#define PACKET_LEN 8192 // Maximus TCP packet size to sniff.

int packetNum = 0; // Number of the packet we are sniffing.

int sniffer(); // Method to sniff TCP packets.
void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *); // Method to handle packets.

/* IP Header */i
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
    union {
        uint16_t flags;
        uint16_t reserved:3, c_flag:1, s_flag:1, t_flag:1, status:10;
    };
    uint16_t cache;
    uint16_t padding;
};

int main()
{
    // ------------------------------- Create Sniffer And Sniff Packets-------------------------------
    sniffer();
    return 0;
}

/********************************
 * Packet Capturing Using Sniffer
 ********************************/

int sniffer() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    // Step 1: Open live pcap session on NIC.
    printf("(!) Opening device for sniffing...\n");
    handle = pcap_open_live("lo", PACKET_LEN, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    printf("(!) Setting the filter for TCP packets only.\n");
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    // Step 4: Close the handle
    pcap_close(handle);

    return 0;
}

/*****************
 * Packet Handling
 *****************/

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // Creating pointer to the ethernet header.
    struct ether_header *eth = (struct ether_header *) packet;

    if (ntohs(eth -> ether_type) == 0x0800) { // 0x0800 is IP type
        // Creating pointer to the ip header.
        struct ip_header *ip = (struct ip_header *) (packet + sizeof(struct ether_header));
        // Creating pointer to the tcp header.
        struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ether_header) + ip -> iph_ihl * 4);
        // Creating pointer to the app header.
        struct app_header *app = (struct app_header *) (packet + sizeof(struct ether_header)
                + ip -> iph_ihl * 4 + tcp -> th_off * 4);
        if (tcp -> psh) {
            // Creating file pointer in "appending" state.
            FILE *file_pointer;
            file_pointer = fopen("325092781_318848413", "a");
            // Check if file opened successfully.
            if (file_pointer == NULL) {
                perror("(-) Could not open file\n");
                exit(EXIT_FAILURE);
            }

            // Converting the unix_time to time format and storing it as a string.
            char time[32];
            time_t t = (time_t) ntohl(app -> unixtime);
            struct tm *unix_time = localtime(&t);
            strftime(time, 20, "%Y-%m-%d %H:%M:%S", unix_time);

            app -> flags = ntohs(app->flags);
            // Outputting to the file the packet's header.
            printf("(+) Packet #%d data is being copied to the the file.\n", packetNum);
            fprintf(file_pointer, "---------------------> Packet: %d <---------------------"
                                  "\n\n>>>>>>>>>>>>>>>>>>>> IP Header <<<<<<<<<<<<<<<<<<<<<<<\n"
                                  "\n(*) source_ip: %s\n(*) dest_ip: %s\n"
                                  "\n>>>>>>>>>>>>>>>>>>>> TCP Header <<<<<<<<<<<<<<<<<<<<<<<\n"
                                  "\n(*) source_port: %d\n(*) dest_port: %d\n"
                                  "\n>>>>>>>>>>>>>>>>>>>> APP Header <<<<<<<<<<<<<<<<<<<<<<<\n"
                                  "\n(*) timestamp: %s\n(*) total_length: %u\n(*) cache_flag: %u\n(*) steps_flag: %u\n"
                                  "(*) type_flag: %u\n(*) status_code: %u\n(*) cache_control: %u\n"
                                  "\n>>>>>>>>>>>>>>>>>>>>>> PAYLOAD <<<<<<<<<<<<<<<<<<<<<<<<<\n",
                    packetNum++, inet_ntoa(ip -> iph_sourceip), inet_ntoa(ip -> iph_destip), ntohs(tcp -> th_sport),
                    ntohs(tcp -> th_dport), time, ntohs(app -> length), (app -> flags >> 12) & 1,
                    (app -> flags >> 11) & 1, (app -> flags >> 10) & 1, app -> status, ntohs(app -> cache));
            packet = packet + sizeof(struct ether_header) + ip -> iph_ihl * 4 + tcp -> th_off * 4 + 12;

            // Outputting the data to the file
            for (int i = 0; i < header->len; i++) {
                if (!(i & 15)) fprintf(file_pointer, "\n  %04X:  ", i);
                fprintf(file_pointer, "%02X ", ((unsigned char *) packet)[i]);
            }
            fprintf(file_pointer, "\n\n");

            // closing the file.
            fclose(file_pointer);
        }
    }
}