// Created by Shalev Ben David and Ron Shuster.

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define P 20

int main(int argc, char *argv[]) {
    // Create socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {  // Creating datagram socket.
        perror("(-) Could not create socket : %d", errno); // Print in case of an error in creating socket.
        return -1;
    }
    else {
        printf("(+) Socket created successfully.\n");
    }

    // Setup gatewayAddress structure
    struct sockaddr_in gatewayAddress;
    memset((char *)&gatewayAddress, 0, sizeof(gatewayAddress));
    unsigned int gatewayAddressLen = sizeof(gatewayAddress);

    // Assign port and address to "gatewayAddress".
    gatewayAddress.sin_family = AF_INET;
    gatewayAddress.sin_port = htons(P); // Short, network byte order.
    gatewayAddress.sin_addr.s_addr = INADDR_ANY;

    // Setup clientAddress structure
    struct sockaddr_in clientAddress;
    memset(&clientAddress, 0, sizeof(clientAddress));
    unsigned int clientAddressLen = sizeof(clientAddress);

    // Assign port (P + 1) and address to "gatewayAddress".
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_port = htons(P + 1); // Short, network byte order.
    clientAddress.sin_addr.s_addr = inet_addr(argv[1]);;

    // Keep listening for data
    while (1)
    {
        int recv_len = -1;
        char buffer[1000];
        // Try to receive some data.
        if ((recv_len = recvfrom(sock, buffer, sizeof(buffer) -1, 0, (struct sockaddr *) &gatewayAddress, &clientAddressLen)) == -1)
        {
            perror("(-) recvfrom() failed with error code : %d", errno);
            break;
        }

        char clientIPAddrReadable[32] = { '\0' };
        inet_ntop(AF_INET, &gatewayAddress.sin_addr, clientIPAddrReadable, sizeof(clientIPAddrReadable));

        //print details of the client/peer and the data received
        printf("(*) Received packet from %s:%d\n", clientIPAddrReadable, ntohs(gatewayAddress.sin_port));

        //now reply to the Client
        if (sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*) &clientAddress, clientAddressLen) == -1){
            perror("(-) sendto() failed with error code : %d", errno);
            break;
        }
        else {
            printf("(*) Sent the message from gateway to the host (%s)", argv[1]);
        }
    }

}
