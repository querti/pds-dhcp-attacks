/*
 * Autor: Lubomir Gallovic (xgallo03)
 * Datum: 5.3.2018
 * Soubor: common.h
 * Komentar: hlavickovy subor
 */

#include <unistd.h>
#include <iostream>
#include <thread>
#include <string> 
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>
#include <mutex>
#include <csignal>
#include <stdbool.h>
#include <cerrno>
#include <signal.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fstream>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <chrono>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <algorithm>

#define CONCURRENT_PACKETS 100
#define TIMEOUT_LENGTH 60
#define ROGUE_TIMEOUT_LENGTH 60
#define MAX_TRIES 3
#define FLOOD_INTERVAL 100
#define BUFLEN 1024 
#define SERVER_PORT 67
#define CLIENT_PORT 68

#define MAC_LENGTH 6
#define BOOT_REQUEST 1
#define BOOT_REPLY 2
#define ETHERNET 1
#define DHCP_OPTION 53
#define REQUESTED_IP 50
#define SERVER_IDENTIFIER 54
#define OPTIONS_END 255
#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5
#define DHCP_RELEASE 7
#define DHCP_RENEW 9
#define DHCP_REBIND 10
#define RENEWAL_TIME 58
#define REBINDING_TIME 59
#define LEASE_TIME 51
#define GATEWAY 3
#define DNS 6
#define DOMAIN_NAME 10
#define MASK 1

//using namespace std;

typedef struct dhcphdr
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t cookie;
    uint8_t options[1024];
} dhcphdr;

typedef struct udphdr
{
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
} udphdr;

typedef struct ethhdr
{
    uint8_t dest[6];
    uint8_t source[6];
    uint16_t type;
} ethhdr;

typedef struct packetInfo
{
	uint32_t xid;
	uint32_t unixTime;
	uint8_t macAddress[6];
    uint32_t address;
    bool confirmed;
    uint32_t renewalTime;
    uint32_t rebindingTime;
    uint32_t leaseTime;
    uint32_t serverAddress;
    uint32_t serverID;
    bool taken;
    int tries;
    uint8_t serverMac[6];
} packetInfo;

typedef struct lentAddress
{
    uint32_t xid;
    uint32_t address;
    uint16_t flags;
    uint32_t giaddr;
    uint8_t chaddr[16];
    bool gateway;
    bool dnsServer;
    bool domain;
    int transactionStage;
    uint32_t unixTime;

} lentAddress;

extern std::vector<packetInfo> sentPackets;
extern pcap_t *handle;
extern std::mutex threadAccess;
extern std::vector<lentAddress> lentAddresses;
extern std::vector<uint32_t> lentFakeAddresses;
extern uint32_t minIP, maxIP;
extern uint32_t gateway;
extern uint32_t dns;
extern char *domain;
extern uint32_t leaseTime, renewTime, rebindTime;
extern uint32_t myIP;
extern uint32_t realMask;
extern unsigned int socketClient;

class PacketCreator {
public:
    int type;
    char packet[2048];
    struct packetInfo *currentPacket;
    struct lentAddress *lentClientAddress;
    uint32_t serverID;
    PacketCreator();

    PacketCreator(int type, struct packetInfo *currentPacket, struct lentAddress *lentClientAddress, uint32_t *serverID);
    char * getPacket();
    struct packetInfo * getPacketInfo();
    int fillPacket();
    int fillDHCP(struct dhcphdr *dhcpHeader);
    int fillOptions(struct dhcphdr *dhcpHeader);
    int fillUDP(struct udphdr *udpHeader, int packetSize);
    int fillIP(struct ip *ipHeader, int packetSize);
    int fillEth(struct ethhdr *ethHeader);
};

void floodDiscovery();
void watchTimeout();
uint32_t convertTime(struct dhcphdr *dhcpHeader, int position);
uint8_t getMessageType(struct dhcphdr *dhcpHeader, uint32_t *serverID);
void renewIP(struct packetInfo *currentPacket);
int sendRequest(struct dhcphdr *dhcpHeader, uint32_t *serverID);
int confirmAck(struct dhcphdr *dhcpHeader, struct ip *ipHeader, struct ethhdr *ethHeader);
void socketClientListener();
