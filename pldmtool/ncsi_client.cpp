#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <sys/un.h>
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include <vector>

int main(int argc, char const *argv[]) 
{
   std::vector<uint8_t> requestMsg = {81, 129, 2, 17, 1, 0, 0};

    const char devPath1[] = "\0dharshan-mux";

    int sockFd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (-1 == sockFd)
    {
        perror("socket failed"); 
        return -1;
    }

    struct sockaddr_un addr
    {};
    addr.sun_family = AF_UNIX;

    memcpy(addr.sun_path, devPath1, sizeof(devPath1) - 1);

    int result = connect(sockFd, reinterpret_cast<struct sockaddr*>(&addr),
                         sizeof(devPath1) + sizeof(addr.sun_family) - 1);
    if (-1 == result)
    {
        perror("Connect failed"); 
        return -1;
    }
    std::vector<uint8_t> responseMsg;

    send(sockFd , requestMsg.data(), requestMsg.size(), 0 ); 
   // printf("Hello message sent\n");

   ssize_t peekedLength = recv(sockFd, nullptr, 0, MSG_TRUNC | MSG_PEEK);
    printf("peekedLength : %d\n", peekedLength);

    responseMsg.resize(peekedLength);

    auto recvDataLength =
                recv(sockFd, reinterpret_cast<void*>(responseMsg.data()),
                     peekedLength, 0);

    printf("recvDataLength : %d\n", recvDataLength);
    //valread = read( sockFd , buffer, 1024); 

             printf("Response Payload:\n");
             for (ssize_t i = 0; i < peekedLength; ++i) {
                     printf("0x%02x ", responseMsg[i]);
                     }
             printf("\n");

    return 0; 
    
}
