#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

typedef struct Sniffer
{
    pcap_t *handle;
    const char *device;
    struct pcap_pkthdr header;
    const u_char *packet;
    unsigned int packet_len;
}Sniffer_t;

typedef struct NetworkLayer
{
    struct Sniffer base;
    void (*parse_ip)(struct NetworkLayer *self, const u_char *packet);
}NetworkLayer_t;

typedef struct TransportLayer
{
    struct NetworkLayer base;
    void (*parse_tcp)(struct TransportLayer *self, const u_char *packet);
    void (*parse_udp)(struct TransportLayer *self, const u_char *packet);
}TransportLayer_t;

typedef struct ApplicationLayer
{
    struct TransportLayer base;
    void (*parse_http)(struct ApplicationLayer *self, const u_char *packet);
    void (*parse_httpu)(struct ApplicationLayer *self, const u_char *packet);
}ApplicationLayer_t;

void parse_ip(NetworkLayer_t *self, const u_char *packet)
{
    struct ip *ip_header = (struct ip *)(packet + 14);
    printf("IP Protocol: %d\n", ip_header->ip_p);
    printf("Source Address: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination Address: %s\n", inet_ntoa(ip_header->ip_dst));
}

void parse_tcp(TransportLayer_t *self, const u_char *packet)
{
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
    unsigned char *tcp_data = (unsigned char *)(packet + 14 + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4));
    int data_size =  ntohs(ip_header->ip_len) - sizeof(ip_header) - sizeof(tcp_header);
    printf("TCP Detected.\n");
    if((memmem(tcp_data, data_size, "BitTorrent", 10) != NULL) || (memmem(tcp_data, data_size, "info_hash", 9) != NULL))
    {
        printf("BitTorrent Detected.\n");
    }
    for(int i = 0; i < data_size; i++)
    {
        if(((tcp_data[i] >= 32) && (tcp_data[i] <= 128)) || (tcp_data[i] == '\n'))
        {
            printf("%c", tcp_data[i]);
        }
        else
        {
            printf(".");
        }
    }
    printf("\n\n\n");
}

void parse_udp(TransportLayer_t *self, const u_char *packet)
{
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
    unsigned char *udp_data = (unsigned char *)(packet + 14 + (ip_header->ip_hl * 4) + sizeof(udp_header));
    int data_size = ntohs(udp_header->uh_ulen) - sizeof(ip_header) - sizeof(udp_header);
    printf("UDP Detected.\n");
    if((memmem(udp_data, data_size, "d1:ad2:id20", 11) != NULL) || (memmem(udp_data, data_size, "info_hash", 9) != NULL) || (memmem(udp_data, data_size, "find_node", 9) != NULL) || (memmem(udp_data, data_size, "announce", 8) != NULL) || (memmem(udp_data, data_size, "\x00\x00\x04\x17\x27\x10\x19\x80", 8) != NULL))
    {
        printf("BitTorrent Detected.\n");
    }
    for(int i = 0; i < data_size; i++)
    {
        if(((udp_data[i] >= 32) && (udp_data[i] <= 128)) || (udp_data[i] == '\n'))
        {
            printf("%c", udp_data[i]);
        }
        else
        {
            printf(".");
        }
    }
    printf("\n\n\n");
}

void parse_http(ApplicationLayer_t *self, const u_char *packet)
{
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
    unsigned char *http_data = (unsigned char *)(packet + 14 + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4));
    int data_size =  ntohs(ip_header->ip_len) - sizeof(ip_header) - sizeof(tcp_header);
    if((memmem(http_data, data_size, "GET /", 5) != NULL) || (memmem(http_data, data_size, "POST /", 6) != NULL) || (memmem(http_data, data_size, "HTTP/", 5) != NULL))
    {
        printf("HTTP Detected.\n");
        if((memmem(http_data, data_size, "info_hash", 9) != NULL) || (memmem(http_data, data_size, "Infohash", 8) != NULL) || (memmem(http_data, data_size, "GET /ann", 8) != NULL) || (memmem(http_data, data_size, "announce", 8) != NULL) || (memmem(http_data, data_size, "x-bittorrent", 12) != NULL))
        {
            printf("BitTorrent Detected.\n");
        }
        for(int i = 0; i < data_size; i++)
        {
            if(((http_data[i] >= 32) && (http_data[i] <= 128)) || (http_data[i] == '\n'))
            {
                printf("%c", http_data[i]);
            }
            else
            {
                printf(".");
            }
        }
        printf("\n\n\n");
    }
}

void parse_httpu(ApplicationLayer_t *self, const u_char *packet)
{
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
    unsigned char *udp_data = (unsigned char *)(packet + 14 + (ip_header->ip_hl * 4) + sizeof(udp_header));
    int data_size = ntohs(udp_header->uh_ulen) - sizeof(ip_header) - sizeof(udp_header);
    if((memmem(udp_data, data_size, "GET /", 5) != NULL) || (memmem(udp_data, data_size, "POST /", 6) != NULL) || (memmem(udp_data, data_size, "HTTP/", 5) != NULL))
    {
        printf("HTTP over UDP Detected.\n");
        if((memmem(udp_data, data_size, "info_hash", 9) != NULL) || (memmem(udp_data, data_size, "Infohash", 8) != NULL) || (memmem(udp_data, data_size, "GET /ann", 8) != NULL) || (memmem(udp_data, data_size, "announce", 8) != NULL) || (memmem(udp_data, data_size, "x-bittorrent", 12) != NULL))
        {
            printf("BitTorrent Detected.\n");
        }
        for(int i = 0; i < data_size; i++)
        {
            if(((udp_data[i] >= 32) && (udp_data[i] <= 128)) || (udp_data[i] == '\n'))
            {
                printf("%c", udp_data[i]);
            }
            else
            {
                printf(".");
            }
        }
        printf("\n\n\n");
    }
}

int main()
{
    char *device = "enp0s3";
    struct ip *ip_header;
    Sniffer_t *sniffer = (Sniffer_t *)malloc(sizeof(Sniffer_t));
    sniffer->device = device;
    sniffer->handle = NULL;

    sniffer->handle = pcap_open_live(sniffer->device, BUFSIZ, 1, 1000, NULL);
    if(sniffer->handle == NULL)
    {
        printf("Error opening device %s\n", sniffer->device);
        return 1;
    }
    printf("Started capturing on %s\n", sniffer->device);

    while(1)
    {
        sniffer->packet = pcap_next(sniffer->handle, &sniffer->header);
        if(sniffer->packet)
        {
            ip_header = (struct ip *)(sniffer->packet + 14);
            if(ip_header->ip_p == 6)
            {
                parse_tcp(sniffer, sniffer->packet);
                parse_http(sniffer, sniffer->packet);
            }
            if(ip_header->ip_p == 17)
            {
                parse_udp(sniffer, sniffer->packet);
                parse_httpu(sniffer, sniffer->packet);
            }
        }
    }

    if(sniffer->handle)
    {
        pcap_close(sniffer->handle);
    }
    free(sniffer);

    return 0;
}

