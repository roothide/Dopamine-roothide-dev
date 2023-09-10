#ifndef _REMOTE_LOG_H_
#define _REMOTE_LOG_H_

#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>
#import <arpa/inet.h>
#include <errno.h>
#include <string.h>

// change this to match your destination (server) IP address
#define RLOG_IP_ADDRESS "255.255.255.255"
#define RLOG_PORT 11909

int sd=0;
struct sockaddr_in broadcastAddr={0};

__attribute__((unused)) static void RLogv(NSString* format, va_list args)
{
        NSString* str = [[NSString alloc] initWithFormat:format arguments:args];

    //static int inited=0;
    //if(inited==0) 
    {
        //inited=1;
        printf("[RemoteLog]  init\n");

         sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sd <= 0)
        {
            printf("[RemoteLog] Error: Could not open socket\n");
            return;
        }

        int broadcastEnable = 1;
        int ret = setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
        if (ret)
        {
            printf("[RemoteLog] Error: Could not open set socket to broadcast mode\n");
            close(sd);
            return;
        }

        // int sendbufsize = 1024*1024*5; //max on ios
        // ret = setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &sendbufsize, sizeof(sendbufsize));
        // if (ret)
        // {
        //     printf("[RemoteLog] Error: Could not set sock buf size, %d, %s\n", errno, strerror(errno));
        //     close(sd);
        //     return;
        // }

        memset(&broadcastAddr, 0, sizeof broadcastAddr);
        broadcastAddr.sin_family = AF_INET;
        inet_pton(AF_INET, RLOG_IP_ADDRESS, &broadcastAddr.sin_addr);
        broadcastAddr.sin_port = htons(RLOG_PORT);

    }

        char* request = (char*)[str UTF8String];
        int ret = sendto(sd, request, strlen(request), 0, (struct sockaddr*)&broadcastAddr, sizeof broadcastAddr);
        
        if (ret < 0)
        {
            printf("[RemoteLog] Error: Could not send broadcast, %d, %s\n", errno, strerror(errno));
            //close(sd);
            return;
        }

        close(sd);

        //printf("send %s\n", request);
}

__attribute__((unused)) static void RLog(NSString* format, ...)
{
        va_list args;
        va_start(args, format);
        RLogv(format, args);
        va_end(args);
}


#endif
