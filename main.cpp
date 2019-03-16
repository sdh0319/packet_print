#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <fstream>

using namespace std;

struct ether_header{
    uint8_t smac[6];
    uint8_t dmac[6];
    uint16_t type;
};

struct ipv4_header{
    uint8_t h_len:4;
    uint8_t ip_v:4;
    uint8_t tos;
    uint16_t ip_len;
    uint16_t iden;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t sip[4];
    uint8_t dip[4];
};

struct tcp_header{
    uint8_t sport[2];
    uint8_t dport[2];
    uint8_t seq[4];
    uint8_t ack[4];
    uint8_t h_len:4;
    uint8_t flag:12;
    uint16_t wid_size;
    uint16_t checksum;
    uint16_t urgent_p;
};

int main(){
    uint8_t  packet[]={
        "\x00\x50\x56\xe2\x95\xda\x00\x0c\x29\x6a\x85\x13\x08\x00\x45\x00" \
        "\x01\x63\x92\x72\x40\x00\x40\x06\xc7\xdb\xc0\xa8\x4b\xa2\xaf\xd5" \
        "\x23\x27\x9e\x32\x00\x50\x24\x50\x20\xf0\x1d\x97\x23\x45\x50\x18" \
        "\x72\x10\xe0\x9c\x00\x00\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50" \
        "\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x74\x65\x73\x74" \
        "\x2e\x67\x69\x6c\x67\x69\x6c\x2e\x6e\x65\x74\x0d\x0a\x55\x73\x65" \
        "\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61" \
        "\x2f\x35\x2e\x30\x20\x28\x58\x31\x31\x3b\x20\x4c\x69\x6e\x75\x78" \
        "\x20\x78\x38\x36\x5f\x36\x34\x3b\x20\x72\x76\x3a\x35\x32\x2e\x30" \
        "\x29\x20\x47\x65\x63\x6b\x6f\x2f\x32\x30\x31\x30\x30\x31\x30\x31" \
        "\x20\x46\x69\x72\x65\x66\x6f\x78\x2f\x35\x32\x2e\x30\x0d\x0a\x41" \
        "\x63\x63\x65\x70\x74\x3a\x20\x74\x65\x78\x74\x2f\x68\x74\x6d\x6c" \
        "\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74" \
        "\x6d\x6c\x2b\x78\x6d\x6c\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69" \
        "\x6f\x6e\x2f\x78\x6d\x6c\x3b\x71\x3d\x30\x2e\x39\x2c\x2a\x2f\x2a" \
        "\x3b\x71\x3d\x30\x2e\x38\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x4c" \
        "\x61\x6e\x67\x75\x61\x67\x65\x3a\x20\x65\x6e\x2d\x55\x53\x2c\x65" \
        "\x6e\x3b\x71\x3d\x30\x2e\x35\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d" \
        "\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70\x2c\x20" \
        "\x64\x65\x66\x6c\x61\x74\x65\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74" \
        "\x69\x6f\x6e\x3a\x20\x6b\x65\x65\x70\x2d\x61\x6c\x69\x76\x65\x0d" \
        "\x0a\x55\x70\x67\x72\x61\x64\x65\x2d\x49\x6e\x73\x65\x63\x75\x72" \
        "\x65\x2d\x52\x65\x71\x75\x65\x73\x74\x73\x3a\x20\x31\x0d\x0a\x0d\x0a"};
    uint8_t *pkt;
    pkt = packet;

    struct ether_header *eth = (struct ether_header*) pkt;

    cout << "-----------------------ethernet header----------------------------" << endl;
    printf("source mac: %02x:%02x:%02x:%02x:%02x:%02x \n",(*eth).smac[0],(*eth).smac[1],(*eth).smac[2],(*eth).smac[3],(*eth).smac[4],(*eth).smac[5]);
    printf("Des mac: %02x:%02x:%02x:%02x:%02x:%02x \n",(*eth).dmac[0],(*eth).dmac[1],(*eth).dmac[2],(*eth).dmac[3],(*eth).dmac[4],(*eth).dmac[5]);
    //printf("ether type 0x%04x\n",ntohs((*eth).type));

    pkt += sizeof(struct ether_header);

    struct ipv4_header *iph = (struct ipv4_header*) pkt;
    cout << "-----------------------ip header----------------------------" << endl;
    printf("source IP:%d.%d.%d.%d\n",(*iph).sip[0],(*iph).sip[1],(*iph).sip[2],(*iph).sip[3] );
    printf("Des IP:%d.%d.%d.%d\n",(*iph).dip[0],(*iph).dip[1],(*iph).dip[2],(*iph).dip[3] );

    pkt += sizeof(struct ipv4_header);

    struct tcp_header *tph = (struct tcp_header*) pkt;
    cout << "-----------------------tcp header----------------------------" << endl;
    printf("source port:%d \n", int((*tph).sport[0]<<8)+int((*tph).sport[1]));
    printf("Des port:%d \n", int((*tph).dport[0]<<8)+int((*tph).dport[1]));

    pkt += sizeof (struct tcp_header);

    for(int i=0;i<16;i++)
        cout << pkt[i];
    return 0;
}
