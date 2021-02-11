#include <iostream>
#include <sys/un.h>
#include <stdio.h>  
#include <string.h>   //strlen  
#include <stdlib.h>  
#include <errno.h>  
#include <unistd.h>   //close  
#include <arpa/inet.h>    //close  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros  
#include <vector>

#include "ncsi_util.hpp"

extern int ncsi_data_len;
extern char *ncsi_data;

using namespace phosphor::network;
using namespace phosphor::network::ncsi;

#define TRUE   1  
#define FALSE  0  
#define PORT 8888  
 
int main(int argc , char *argv[])   
{  
    static char sockname[] = "\0dharshan-mux";
    int namelen = sizeof(sockname) - 1;
    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, sockname, namelen);
//    uint8_t buffer[1024] = {0}; 
    std::vector<uint8_t> requestMsg;
    

    int opt = TRUE;   
    int master_socket , addrlen , new_socket , client_socket[30] ,  
          max_clients = 30 , activity, i , valread , sd;   
    int max_sd;   
         
         
    //set of socket descriptors  
    fd_set readfds;   
         
     
    //initialise all client_socket[] to 0 so not checked  
    for (i = 0; i < max_clients; i++)   
    {   
        client_socket[i] = 0;   
    }   
         
    //create a master socket  
    if( (master_socket = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == 0)   
    {   
        perror("socket failed");   
        exit(EXIT_FAILURE);   
    }   
     
    //set master socket to allow multiple connections ,  
    //this is just a good habit, it will work without this  
    if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,  
          sizeof(opt)) < 0 )   
    {   
        perror("setsockopt");   
        exit(EXIT_FAILURE);   
    }   
     
    //bind the socket to localhost port 8888  
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address.sun_family) + namelen)<0)   
    {   
        perror("bind failed");   
        exit(EXIT_FAILURE);   
    }   
    printf("Listener on port %d \n", PORT);   
         
    //try to specify maximum of 3 pending connections for the master socket  
    if (listen(master_socket, 3) < 0)   
    {   
        perror("listen");   
        exit(EXIT_FAILURE);   
    }   
         
    //accept the incoming connection  
    addrlen = sizeof(address);   
    puts("Waiting for connections ...");   
         
    while(TRUE)   
    {   
        //clear the socket set  
        FD_ZERO(&readfds);   
     
        //add master socket to set  
        FD_SET(master_socket, &readfds);   
        max_sd = master_socket;   
             
        //add child sockets to set  
        for ( i = 0 ; i < max_clients ; i++)   
        {   
            //socket descriptor  
            sd = client_socket[i];   
                 
            //if valid socket descriptor then add to read list  
            if(sd > 0)   
                FD_SET( sd , &readfds);   
                 
            //highest file descriptor number, need it for the select function  
            if(sd > max_sd)   
                max_sd = sd;   
        }   
     
        //wait for an activity on one of the sockets , timeout is NULL ,  
        //so wait indefinitely  
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);   
       
        if ((activity < 0) && (errno!=EINTR))   
        {   
            printf("select error");   
        }   
             
        //If something happened on the master socket ,  
        //then its an incoming connection  
        if (FD_ISSET(master_socket, &readfds))   
        {   
            if ((new_socket = accept(master_socket,  
                    (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)   
            {   
                perror("accept");   
                exit(EXIT_FAILURE);   
            }   
             
            auto peeked_length = recv(new_socket, NULL, 0, MSG_PEEK | MSG_TRUNC);
            std::cerr <<"peeked_length : " << peeked_length <<"\n";

            requestMsg.resize(peeked_length);

            auto recvDataLength =
                recv(new_socket, reinterpret_cast<void*>(requestMsg.data()),
                     peeked_length, 0);

    printf("recvDataLength : %d\n", recvDataLength);

            //valread = read( new_socket , buffer, 1024);
            std::cerr <<" The request buffer form client with the length  : "<< recvDataLength <<"\n" ;
            for(int i = 0; i< recvDataLength ; i++)
            {
                std::cerr << (int)requestMsg[i] ;
            }
            std::cerr <<"\n";


            int package = 0;
            int channel = 0;
            int ifindex = 2;
            int opcode  = 81;
            short payload_length = peeked_length;
           // uint8_t* payload = buffer;
             
            sendCommand(ifindex, package, channel, opcode, payload_length, requestMsg.data());

            printf("NCSI Response Payload length = %d\n", ncsi_data_len);
             printf("Response Payload:\n");
             for (int i = 0; i < ncsi_data_len; ++i) {
                     printf("0x%02x ", *(ncsi_data+i));
                     }   
             printf("\n");


            //send new connection greeting message  
            //send(new_socket, ncsi_data, ncsi_data_len, 0);
            send(new_socket, ncsi_data+20, ncsi_data_len-20, 0);
                 
            //puts("Welcome message sent successfully");
            requestMsg.clear();
            close(new_socket);         
            //add new socket to array of sockets  
            for (i = 0; i < max_clients; i++)   
            {   
                //if position is empty  
                if( client_socket[i] == 0 )   
                {   
                    client_socket[i] = new_socket;   
                    printf("Adding to list of sockets as %d\n" , i);   
                         
                    break;   
                }   
            }   
        }   
             
        //else its some IO operation on some other socket 
        for (i = 0; i < max_clients; i++)   
        {   
            sd = client_socket[i];   
                 
            if (FD_ISSET( sd , &readfds))   
            {   
                //Check if it was for closing , and also read the  
                //incoming message  
                if ((valread = read( sd , reinterpret_cast<void*>(requestMsg.data()), requestMsg.size())) == 0)   
                {   
                    printf("Host disconnected");
                         
                    //Close the socket and mark as 0 in list for reuse  
                    close( sd );   
                    client_socket[i] = 0;   
                }   
                     
                //Echo back the message that came in  
                else 
                {   
                    //set the string terminating NULL byte on the end  
                    //of the data read  
                   // buffer[valread] = '\0';   
                    //send(sd , buffer , 1024 , 0 );   
                    requestMsg.clear();
                }   
            }   
        }
        requestMsg.clear();
    }   
         
    return 0;   
}   

