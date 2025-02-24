#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

typedef struct Flow
{
    int packet_count;
    long long int time_of_start;
    long long int last_seen;
    char ip_source[16];
    char ip_destination[16];
    char protocol[4];
    unsigned int port_source;
    unsigned int port_destination;
    int alertness;
}Flow;

typedef struct Sniffer
{
    pcap_t *handle;
    const char *device;
    struct pcap_pkthdr header;
    const u_char *packet;
    unsigned int packet_len;
}Sniffer_t;

int main()
{
    char *device = "enp0s3";
    struct ip *ip_header;
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    struct Flow *FlowDB = (Flow *)malloc(1000 * sizeof(Flow));
    int flow_count = 0;
    int flow_in_flag = 0;
    struct timeval tv;
    double cur_time, prev_time;
    int alertness = 0;
    double avg_time = 0;
    int j = 0;

    int alertness_needed = 5;
    double avg_time_needed = 0.15;

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
            gettimeofday(&tv, NULL);
            cur_time = tv.tv_sec + 1.0e-6 * tv.tv_usec;
            prev_time = cur_time;
            if(ip_header->ip_p == 6)
            {
                tcp_header = (struct tcphdr *)(sniffer->packet + 14 + (ip_header->ip_hl * 4));
                for(int i = flow_count; i > 0; i--)
                {
                    if((strcmp(inet_ntoa(ip_header->ip_src), FlowDB[i].ip_source) == 0) && (strcmp(inet_ntoa(ip_header->ip_dst), FlowDB[i].ip_destination) == 0) && (ntohs(tcp_header->th_sport) == FlowDB[i].port_source) && (ntohs(tcp_header->th_dport) == FlowDB[i].port_destination))
                    {
                        FlowDB[i].packet_count++;
                        FlowDB[i].last_seen = cur_time;
                        flow_in_flag = 1;
                        break;
                    }
                    if((strcmp(inet_ntoa(ip_header->ip_src), FlowDB[i].ip_source) == 0) && (strcmp(inet_ntoa(ip_header->ip_dst), FlowDB[i].ip_destination) != 0) && (ntohs(tcp_header->th_sport) == FlowDB[i].port_source))
                    {
                        alertness++;
                        if(alertness <= alertness_needed)
                        {
                            avg_time = avg_time + (prev_time - FlowDB[i].last_seen);
                            prev_time = FlowDB[i].last_seen;
                            j++;
                        }
                    }
                }
                if(flow_in_flag == 0)
                {
                    FlowDB[flow_count].packet_count = 1;
                    FlowDB[flow_count].time_of_start = cur_time;
                    FlowDB[flow_count].last_seen = cur_time;
                    strcpy(FlowDB[flow_count].ip_source, inet_ntoa(ip_header->ip_src));
                    strcpy(FlowDB[flow_count].ip_destination, inet_ntoa(ip_header->ip_dst));
                    FlowDB[flow_count].port_source = ntohs(tcp_header->th_sport);
                    FlowDB[flow_count].port_destination = ntohs(tcp_header->th_dport);
                    strcpy(FlowDB[flow_count].protocol, "TCP");
                    if(alertness >= alertness_needed)
                    {
                        if((avg_time / j) <= avg_time_needed)
                        {
                            printf("BitTorrent detected on IP: %s and Port: %u. L4 Protocol - %s.\n", FlowDB[flow_count].ip_source, FlowDB[flow_count].port_source, FlowDB[flow_count].protocol);
                        }
                    }
                    flow_count++;
                }
                alertness = 0;
                avg_time = 0;
                j = 0;
            }
            if(ip_header->ip_p == 17)
            {
                udp_header = (struct udphdr *)(sniffer->packet + 14 + (ip_header->ip_hl * 4));
                for(int i = flow_count; i > 0; i--)
                {
                    if((strcmp(inet_ntoa(ip_header->ip_src), FlowDB[i].ip_source) == 0) && (strcmp(inet_ntoa(ip_header->ip_dst), FlowDB[i].ip_destination) == 0) && (ntohs(udp_header->uh_sport) == FlowDB[i].port_source) && (ntohs(udp_header->uh_dport) == FlowDB[i].port_destination))
                    {
                        FlowDB[i].packet_count++;
                        FlowDB[i].last_seen = cur_time;
                        flow_in_flag = 1;
                        break;
                    }
                    if((strcmp(inet_ntoa(ip_header->ip_src), FlowDB[i].ip_source) == 0) && (strcmp(inet_ntoa(ip_header->ip_dst), FlowDB[i].ip_destination) != 0) && (ntohs(udp_header->uh_sport) == FlowDB[i].port_source))
                    {
                        alertness++;
                        if(alertness <= alertness_needed)
                        {
                            avg_time = avg_time + (prev_time - FlowDB[i].last_seen);
                            prev_time = FlowDB[i].last_seen;
                            j++;
                        }
                    }
                }
                if(flow_in_flag == 0)
                {
                    FlowDB[flow_count].packet_count = 1;
                    FlowDB[flow_count].time_of_start = cur_time;
                    FlowDB[flow_count].last_seen = cur_time;
                    strcpy(FlowDB[flow_count].ip_source, inet_ntoa(ip_header->ip_src));
                    strcpy(FlowDB[flow_count].ip_destination, inet_ntoa(ip_header->ip_dst));
                    FlowDB[flow_count].port_source = ntohs(udp_header->uh_sport);
                    FlowDB[flow_count].port_destination = ntohs(udp_header->uh_dport);
                    strcpy(FlowDB[flow_count].protocol, "UDP");
                    if(alertness >= alertness_needed)
                    {
                        if((avg_time / j) <= avg_time_needed)
                        {
                            printf("BitTorrent detected on IP: %s and Port: %u. L4 Protocol - %s.\n", FlowDB[flow_count].ip_source, FlowDB[flow_count].port_source, FlowDB[flow_count].protocol);
                        }
                    }
                    flow_count++;
                }
                alertness = 0;
                avg_time = 0;
                j = 0;
            }
            flow_in_flag = 0;
        }
        /*for(int i = 0; i < flow_count; i++)
        {
            printf("Flow %d - %s: IPs S/D - %s / %s, Ports S/D - %u / %u, Packets - %d, Start - %lld, Last Seen - %lld\n", i, FlowDB[i].protocol, FlowDB[i].ip_source, FlowDB[i].ip_destination, FlowDB[i].port_source, FlowDB[i].port_destination, FlowDB[i].packet_count, FlowDB[i].time_of_start, FlowDB[i].last_seen);
        }
        printf("\n\n");*/
        if(flow_count == 1000)
        {
            break;
        }
    }

    if(sniffer->handle)
    {
        pcap_close(sniffer->handle);
    }
    free(sniffer);
    free(FlowDB);

    return 0;
}
