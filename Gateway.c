// Created by Shalev Ben David and Ron Shuster.

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

#define P 20 // The port we choose.
#define PACKET_SIZE 1500 // The maximus packet size.

int main(int argc, char *argv[]) {
    int sockGateway;
    if ((sockGateway = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {  // Creating datagram socket for gateway.
        perror("(-) Could not create socket.\n"); // Print in case of an error in creating socket.
        return -1;
    }
    else {
        printf("(+) Socket created successfully.\n");
    }

    // Setup gatewayAddress structure.
    struct sockaddr_in gatewayAddress;
    memset(&gatewayAddress, 0, sizeof(gatewayAddress));
    unsigned int gatewayAddressLen = sizeof(gatewayAddress);

    // Assign port and address to "gatewayAddress".
    gatewayAddress.sin_family = AF_INET; // IPv4
    gatewayAddress.sin_port = htons(P); // Short, network byte order.
    gatewayAddress.sin_addr.s_addr = INADDR_ANY; // Any IP who wants to send the UDP packets.

    // Check if address is already in use.
    int enableReuse = 1;
    if (setsockopt(sockGateway, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(enableReuse)) ==  -1)  {
        perror("setsockopt() failed with error code: %d\n");
        exit(EXIT_FAILURE); // Exit program and return EXIT_FAILURE (defined as 1 in stdlib.h).
    }

    // Bind the gatewayAddress (representing the client on port P) to the socket of the Gateway.
    if (bind(sockGateway, (struct sockaddr *)&gatewayAddress, gatewayAddressLen) == -1) {
        perror("(-) bind() failed with error code.\n");
        close(sockGateway);
        return -1;
    }
    else {
        printf("(+) Binding client to the gateway was successful.\n");
    }

    int sockDest;
    if ((sockDest = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {  // Creating datagram socket for destination.
        perror("(-) Could not create socket.\n"); // Print in cse of an error in creating socket.
        return -1;
    }
    else {
        printf("(+) Socket created successfully.\n");
    }

    // Setup destAddress structure.
    struct sockaddr_in destAddress;
    memset(&destAddress, 0, sizeof(destAddress));
    unsigned int destAddressLen = sizeof(destAddress);

    // Assign port (P + 1) and address to "destAddress".
    destAddress.sin_family = AF_INET; // IPv4
    destAddress.sin_port = htons(P + 1); // Short, network byte order.
    destAddress.sin_addr.s_addr = inet_addr(argv[1]); // The host IP (function argument).

    // Check if address is already in use.
    enableReuse = 1;
    if (setsockopt(sockDest, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(enableReuse)) ==  -1)  {
        perror("setsockopt() failed with error code: %d\n");
        exit(EXIT_FAILURE); // Exit program and return EXIT_FAILURE (defined as 1 in stdlib.h).
    }

    // Bind the destAddress (representing the host on port P + 1) to the socket of the destination.
    if (bind(sockDest, (struct sockaddr *)&destAddress, destAddressLen) == -1) {
        perror("(-) bind() failed with error code.\n");
        close(sockDest);
        return -1;
    }
    else {
        printf("(+) Binding gateway to the host was successful.\n");
    }

    // Keep listening for udp packets.
    while (true) {
        char buffer[PACKET_SIZE] = {0};
        // Receiving data to gateway on port P.
        if (recvfrom(sockGateway, buffer, PACKET_SIZE, 0, (struct sockaddr *) &gatewayAddress, &gatewayAddressLen) == -1){
            perror("(-) recvfrom() failed with error code.\n");
            break;
        }

        // Print details of the client/peer and the data received.
        char clientIPAddrReadable[32] = { '\0' };
        inet_ntop(AF_INET, &gatewayAddress.sin_addr, clientIPAddrReadable, sizeof(clientIPAddrReadable));
        printf("(*) Received packet from %s\n", clientIPAddrReadable);

        // Create random variable and send on a probability of 1/2.
        double chance = ((float) random()) / ((float) RAND_MAX);
        if(chance > 0.5) {
            if (sendto(sockDest, buffer, PACKET_SIZE, 0, (struct sockaddr *) &destAddress, destAddressLen) == -1) {
                perror("(-) sendto() failed with error code.\n");
                break;
            } else {
                printf("(*) Sent the message from gateway to the host (%s)\n", argv[1]);
            }
        } else {
            printf("(-) Didn't send the message!\n");
        }
    }
    close(sockGateway);
    close(sockDest);
}
