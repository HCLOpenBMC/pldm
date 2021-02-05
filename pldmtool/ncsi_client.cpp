#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <sys/un.h>
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 

int main(int argc, char const *argv[]) 
{
    int valread;
    char hello[] = "client sent message";
    char buffer[1024] = {0};
    char *helloo = hello;

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

    send(sockFd , helloo , strlen(helloo) , 0 ); 
    printf("Hello message sent\n"); 
    valread = read( sockFd , buffer, 1024); 

     printf("%s\n",buffer ); 
    return 0; 
    
}
