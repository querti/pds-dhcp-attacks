/*
 * Autor: Lubomir Gallovic (xgallo03)
 * Datum: 5.3.2018
 * Soubor: common.cpp
 * Komentar: zdrojovy kod pouzity v obidvoch zadaniach 
 */

#include "common.h"

std::vector<packetInfo> sentPackets;
pcap_t *handle;
std::mutex threadAccess;
std::vector<lentAddress> lentAddresses;
std::vector<uint32_t> lentFakeAddresses;

uint32_t minIP, maxIP;
uint32_t gateway;
uint32_t dns;
char *domain;
uint32_t leaseTime, renewTime, rebindTime;
uint32_t myIP;
uint32_t realMask;
unsigned int socketClient;


////////////////////////////////////////////////////////////
//PACKET GENERATION
////////////////////////////////////////////////////////////

//copies 32 bit number into byte long cells
void convert32To8(uint32_t message, struct dhcphdr *dhcpHeader, int position) {

	dhcpHeader->options[position++] = message >> 24;
	dhcpHeader->options[position++] = message >> 16;
	dhcpHeader->options[position++] = message >> 8;
	dhcpHeader->options[position++] = message;

}

//***************************************************************************************
//*    Author: Dr Graham D Shaw
//*    Availability: http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
//*
//***************************************************************************************
uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}


PacketCreator::PacketCreator(int type, struct packetInfo *currentPacket, struct lentAddress *lentClientAddress, uint32_t *serverID) {
	this->type = type;

	if (currentPacket == NULL) 
		this->currentPacket = new packetInfo();
	else
		this->currentPacket = currentPacket;

	if (serverID != NULL)
		this->serverID = *serverID;
	else
		this->serverID = 0;
	this->lentClientAddress = lentClientAddress;
}

char * PacketCreator::getPacket() {
	return packet;
}

struct packetInfo * PacketCreator::getPacketInfo() {
	return currentPacket;
}

//creates packet and fills it with randomized information, returns size
int PacketCreator::fillPacket() {

	int packetSize = 0; 

	struct dhcphdr *dhcpHeader;
	struct udphdr *udpHeader;
	struct ip *ipHeader;
	struct ethhdr *ethHeader;

	ethHeader = (struct ethhdr *)(this->packet);
	ipHeader = (struct ip *)(this->packet + sizeof(struct ethhdr));
	udpHeader = (struct udphdr *)(((char *)ipHeader) + sizeof(struct ip));
	dhcpHeader = (struct dhcphdr *)(((char *)udpHeader) + sizeof(struct udphdr));

	packetSize += fillDHCP(dhcpHeader);
	packetSize += fillUDP(udpHeader, packetSize);
	packetSize += fillIP(ipHeader, packetSize);
	packetSize += fillEth(ethHeader);

	return packetSize;
}

int PacketCreator::fillDHCP(struct dhcphdr *dhcpHeader) { 

	if (type == DHCP_DISCOVER || type == DHCP_REQUEST || type == DHCP_RENEW || type == DHCP_REBIND)
		dhcpHeader->op = BOOT_REQUEST;
	else if (type == DHCP_OFFER || type == DHCP_ACK)
		dhcpHeader->op = BOOT_REPLY;

	dhcpHeader->htype = ETHERNET;
	dhcpHeader->hlen = MAC_LENGTH;
	dhcpHeader->hops = 0;

	//generate random xid
	if (type == DHCP_DISCOVER) {
		uint8_t randByte;
		uint32_t randXid = 0;
		for (int i = 0; i <= 3; i++) {

			randXid = randXid << 8;
			randByte = rand() % 256; 
			randXid = randXid | randByte;
		}

		currentPacket->xid = randXid;
		dhcpHeader->xid = htonl(randXid);
	}
	else if (type == DHCP_REQUEST || type == DHCP_RENEW || type == DHCP_REBIND)
		dhcpHeader->xid = htonl(currentPacket->xid);
	else if (type == DHCP_OFFER || type == DHCP_ACK)
		dhcpHeader->xid = htonl(lentClientAddress->xid);

	if (type == DHCP_DISCOVER || type == DHCP_REQUEST)
		currentPacket->unixTime = (uint32_t)time(NULL);

	dhcpHeader->secs = 0;
	//set server broadcast flag
	//IF RENEWING AND REBINDING IP POSSIBLY ONLY UNICAST
	if (type == DHCP_DISCOVER || type == DHCP_REQUEST || type == DHCP_REBIND)
		dhcpHeader->flags = htons(0x8000);
	else if (type == DHCP_RENEW) 
		dhcpHeader->flags = htons(0x0000);
	else if (type == DHCP_OFFER || type == DHCP_ACK)
		//dhcpHeader->flags = htons(lentClientAddress->flags);
		dhcpHeader->flags = htons(0x8000);

	if (type == DHCP_DISCOVER || type == DHCP_REQUEST || type == DHCP_OFFER)
		dhcpHeader->ciaddr = 0;
	else if (type == DHCP_RENEW || type == DHCP_REBIND)
		dhcpHeader->ciaddr = htonl(currentPacket->address);
	else if (type == DHCP_ACK) {
		if (lentClientAddress->transactionStage == DHCP_OFFER)//1st request
			dhcpHeader->ciaddr = 0;
		else if (lentClientAddress->transactionStage == DHCP_ACK)//renew/rebind
			dhcpHeader->ciaddr = htonl(lentClientAddress->address);
	}

	if (type == DHCP_DISCOVER || type == DHCP_REQUEST || type == DHCP_RENEW || type == DHCP_REBIND)
		dhcpHeader->yiaddr = 0;
	else if (type == DHCP_OFFER || type == DHCP_ACK)
		dhcpHeader->yiaddr = htonl(lentClientAddress->address);

	dhcpHeader->siaddr = 0;
	if (type == DHCP_DISCOVER || type == DHCP_REQUEST || type == DHCP_RENEW || type == DHCP_REBIND)
		dhcpHeader->giaddr = 0;
	else if (type == DHCP_OFFER || type == DHCP_ACK)
		dhcpHeader->giaddr = htonl(lentClientAddress->giaddr);

	//spoof mac address
	if (type == DHCP_DISCOVER){
		uint8_t randByte;
		for (int i = 0; i <= 5; i++) {
			randByte = rand() % 256; 
			currentPacket->macAddress[i] = randByte;
			//dhcpHeader->chaddr[i] = randByte; //not like this because endian
		}
		memcpy(dhcpHeader->chaddr, currentPacket->macAddress, 6);
	}
	else if (type == DHCP_REQUEST || type == DHCP_RENEW || type == DHCP_REBIND)
		memcpy(dhcpHeader->chaddr, currentPacket->macAddress, 6);
	else if (type == DHCP_OFFER || type == DHCP_ACK)
		memcpy(dhcpHeader->chaddr, lentClientAddress->chaddr, 16);

	for (int i = 6; i <= 15; i++) //fill rest with 0s
		dhcpHeader->chaddr[i] = 0;
	for (int i = 0; i <= 63; i++) //fill sname
		dhcpHeader->sname[i] = 0;
	for (int i = 0; i <= 127; i++) //fill file
		dhcpHeader->file[i] = 0;

	dhcpHeader->cookie = htonl(0x63825363);

	int size = 240;
	size += fillOptions(dhcpHeader);

	if (type == DHCP_DISCOVER) {
		currentPacket->address = 0;
		currentPacket->confirmed = false;
		currentPacket->renewalTime = 0;
		currentPacket->rebindingTime = 0;
		currentPacket->leaseTime = 0;
		currentPacket->taken = false;
		currentPacket->tries = 0;
	}

	return size;
}

//fills DHCP options
int PacketCreator::fillOptions(struct dhcphdr *dhcpHeader) {

	uintptr_t size = 0;
	//dhcp type
	dhcpHeader->options[size++] = DHCP_OPTION;
	dhcpHeader->options[size++] = 1;
	if (type == DHCP_DISCOVER)
		dhcpHeader->options[size++] = DHCP_DISCOVER;
	else if (type == DHCP_REQUEST || type == DHCP_RENEW || type == DHCP_REBIND)
		dhcpHeader->options[size++] = DHCP_REQUEST;
	else if (type == DHCP_OFFER)
		dhcpHeader->options[size++] = DHCP_OFFER;
	else if (type == DHCP_ACK)
		dhcpHeader->options[size++] = DHCP_ACK;

	//need to include options requested ip and server identifier
	if (type == DHCP_REQUEST) {

		dhcpHeader->options[size++] = REQUESTED_IP;
		dhcpHeader->options[size++] = 4;
		convert32To8(currentPacket->address, dhcpHeader, size);
		size += 4;

		dhcpHeader->options[size++] = SERVER_IDENTIFIER;
		dhcpHeader->options[size++] = 4;
		convert32To8(serverID, dhcpHeader, size);
		size += 4;
	}

	if (type == DHCP_OFFER || type == DHCP_ACK) {

		dhcpHeader->options[size++] = SERVER_IDENTIFIER;
		dhcpHeader->options[size++] = 4;
		convert32To8(myIP, dhcpHeader, size);
		size += 4;

		dhcpHeader->options[size++] = LEASE_TIME;
		dhcpHeader->options[size++] = 4;
		convert32To8(leaseTime, dhcpHeader, size);
		size += 4;

		dhcpHeader->options[size++] = MASK;
		dhcpHeader->options[size++] = 4;
		convert32To8(realMask, dhcpHeader, size);
		size += 4;


		if (lentClientAddress->gateway == true) {
			dhcpHeader->options[size++] = GATEWAY;
			dhcpHeader->options[size++] = 4;
			convert32To8(gateway, dhcpHeader, size);
			size += 4;
		}

		if (lentClientAddress->dnsServer == true) {
			dhcpHeader->options[size++] = DNS;
			dhcpHeader->options[size++] = 4;
			convert32To8(dns, dhcpHeader, size);
			size += 4;
		}

		if (lentClientAddress->domain == true) {
			dhcpHeader->options[size++] = DOMAIN_NAME;
			dhcpHeader->options[size++] = strlen(domain);
			memcpy((void *)dhcpHeader->options[size], domain, strlen(domain));
			size += strlen(domain);
		}
	}

	//end
	dhcpHeader->options[size++] = 255;

	return size;
}

int PacketCreator::fillUDP(struct udphdr *udpHeader, int packetSize) {

	if (type == DHCP_DISCOVER || type == DHCP_REQUEST || type == DHCP_RENEW || type == DHCP_REBIND) {
		udpHeader->source = htons(68);
		udpHeader->dest = htons(67);
	} else if (type == DHCP_OFFER || type == DHCP_ACK) {
		udpHeader->source = htons(67);
		udpHeader->dest = htons(68);
	}

	udpHeader->len = htons(packetSize + 8);
	udpHeader->check = 0;

	return sizeof(struct udphdr);
}

int PacketCreator::fillIP(struct ip *ipHeader, int packetSize) {

	ipHeader->ip_hl = 5;
	ipHeader->ip_v = 4;
	ipHeader->ip_tos = 0;
	ipHeader->ip_len = htons(packetSize + sizeof(struct ip));
	ipHeader->ip_id = htons(0xffff);
	ipHeader->ip_off = 0;
	ipHeader->ip_ttl = 250;
	ipHeader->ip_p = 17;
	ipHeader->ip_sum = 0;

	if (type == DHCP_DISCOVER || type == DHCP_REQUEST) {
		ipHeader->ip_src.s_addr = 0;
		ipHeader->ip_dst.s_addr = 0xFFFFFFFF; //broadcast
	}
	else if (type == DHCP_RENEW) {
		ipHeader->ip_src.s_addr = htonl(currentPacket->address);
		ipHeader->ip_dst.s_addr = htonl(currentPacket->serverAddress);
	}
	else if (type == DHCP_REBIND) {
		ipHeader->ip_src.s_addr = htonl(currentPacket->address);
		ipHeader->ip_dst.s_addr = 0xFFFFFFFF; //broadcast
	}
	else if (type == DHCP_OFFER) {
		ipHeader->ip_src.s_addr = htonl(myIP);
		ipHeader->ip_dst.s_addr = 0xFFFFFFFF; //broadcast
	}
	else if (type == DHCP_ACK) {
		if (lentClientAddress->transactionStage == DHCP_OFFER) {
			ipHeader->ip_src.s_addr = htonl(myIP);
			ipHeader->ip_dst.s_addr = 0xFFFFFFFF; //broadcast
		} else {
			ipHeader->ip_src.s_addr = htonl(myIP);
			ipHeader->ip_dst.s_addr = htonl(lentClientAddress->address);
		}
		
	}
	ipHeader->ip_sum = ip_checksum((unsigned short *) ipHeader, sizeof(struct ip));

	return sizeof(struct ip);

}

int PacketCreator::fillEth(struct ethhdr *ethHeader) {

	if (type == DHCP_RENEW)
		memcpy(ethHeader->dest, currentPacket->serverMac, 6);
	else 
		memset(ethHeader->dest, -1, 6);
	memcpy(ethHeader->source, currentPacket->macAddress, 6);
	ethHeader->type = htons(0x0800);

	return sizeof(struct ethhdr);
}


////////////////////////////////////////////////////////////
//PACKET FLOODING (unsolicited)
////////////////////////////////////////////////////////////

//threaded function, every x ms sends new discover packet 
void floodDiscovery() {

	//int counter = 0;

	while (true) {

		PacketCreator newPacket(DHCP_DISCOVER, NULL, NULL, NULL);
		int size = newPacket.fillPacket();
		char *packet = newPacket.getPacket();
		struct packetInfo *currentPacket = newPacket.getPacketInfo();

		int sent = pcap_inject(handle, packet, size);
		if (sent <= 0) {
			fprintf(stderr, "Error sending discovery packet\n");
			continue;
		}

		threadAccess.lock();
		sentPackets.push_back(*currentPacket);
		threadAccess.unlock();

		std::this_thread::sleep_for(std::chrono::milliseconds(FLOOD_INTERVAL));

		/*counter++;
		if (counter > 30)
			break;*/

	}
}

//threaded function that checks for timeout and removes inactive packets
void watchTimeout() {

	uint32_t currentTime;

	while(true) {

		//check packets every minute
		std::this_thread::sleep_for(std::chrono::seconds(60));

		for (unsigned int i = 0; i < sentPackets.size(); i++) {
			currentTime = (uint32_t)time(NULL);

			if (sentPackets[i].confirmed == false && sentPackets[i].address == 0) { //packet in DISCOVER stage
				if (currentTime - sentPackets[i].unixTime > TIMEOUT_LENGTH) { //throw away and generate new DISCOVER

					threadAccess.lock();
					sentPackets.erase(sentPackets.begin() + i);
					threadAccess.unlock();
				}
			} else if (sentPackets[i].confirmed == false && sentPackets[i].address != 0) {//packet in REQUEST stage
				if (currentTime - sentPackets[i].unixTime > TIMEOUT_LENGTH && sentPackets[i].tries < MAX_TRIES) { //tries few times to resend

					PacketCreator newPacket(DHCP_REQUEST, &(sentPackets[i]), NULL, &(sentPackets[i].serverID));
					int size = newPacket.fillPacket();
					char *packet = newPacket.getPacket();

					threadAccess.lock();
					sentPackets[i].tries++;
					threadAccess.unlock();

					int sent = pcap_inject(handle, packet, size);
					if (sent <= 0)
						fprintf(stderr, "Error sending request packet\n");

				} else if (currentTime - sentPackets[i].unixTime > TIMEOUT_LENGTH && sentPackets[i].tries >= MAX_TRIES) { //if failes, remove

					threadAccess.lock();
					sentPackets.erase(sentPackets.begin() + i);
					threadAccess.unlock();
				}
			}
		}
	}
}

////////////////////////////////////////////////////////////
//DHCP PROTOCOL FOLLOWING
////////////////////////////////////////////////////////////


//gets type of DHCP packet
uint8_t getMessageType(struct dhcphdr *dhcpHeader, uint32_t *serverID) {

	int position = 0;
	int option = -1;

	while (true) {

		if (dhcpHeader->options[position] == DHCP_OPTION) { //found dhcp option
			position += 2;
			option = dhcpHeader->options[position];
			position++;

		} else if (dhcpHeader->options[position] == SERVER_IDENTIFIER) { //get server ID
			position += 2;
			*serverID = ntohl(*((uint32_t *)(&(dhcpHeader->options[position]))));
			position += 4;

		} else if (dhcpHeader->options[position] == OPTIONS_END) {
			break;
		} else { //skip option

			position++;
			position += dhcpHeader->options[position];
			position++;
		}
	}
	return option; //not a DHCP packet
}


//threaded function that attempt to renew and rebind acquired IP after apropriate amount of time
void renewIP(struct packetInfo *currentPacket) {

	//if this time doesnt correspond to current unix time, then this thread is depricated
	uint32_t startTime = currentPacket->unixTime; 
	//slep until renew
	std::this_thread::sleep_for(std::chrono::seconds(currentPacket->renewalTime - (int)(currentPacket->renewalTime*0.10)));

	if (startTime == currentPacket->unixTime) {

		PacketCreator newPacket(DHCP_RENEW, currentPacket, NULL, NULL);
		int size = newPacket.fillPacket();
		char *packet = newPacket.getPacket();

		int sent = pcap_inject(handle, packet, size);
		if (sent <= 0)
			fprintf(stderr, "Error sending request packet\n");

	} else { //thread no longer relevant
		return;
	}
	//sleep until rebind
	std::this_thread::sleep_for(std::chrono::seconds(currentPacket->rebindingTime - currentPacket->renewalTime));

	if (startTime == currentPacket->unixTime) {

		PacketCreator newPacket(DHCP_REBIND, currentPacket, NULL, NULL);
		int size = newPacket.fillPacket();
		char *packet = newPacket.getPacket();

		int sent = pcap_inject(handle, packet, size);
		if (sent <= 0)
			fprintf(stderr, "Error sending request packet\n");

	} else { //thread no longer relevant
		return;
	}
	//sleep until relase
	std::this_thread::sleep_for(std::chrono::seconds(currentPacket->leaseTime - currentPacket->rebindingTime));

	if (startTime != currentPacket->unixTime) {//rebind was successfull
		return;
	} else {

		for (unsigned int i = 0; i < sentPackets.size(); i++) {

			if (sentPackets[i].xid == currentPacket->xid) {
				threadAccess.lock();
				sentPackets.erase(sentPackets.begin() + i);
				threadAccess.unlock();
			}
		}
	}
}


//checks for sent DHCP discover messages and sends appropriate DHCP request message
int sendRequest(struct dhcphdr *dhcpHeader, uint32_t *serverID) {

	for (unsigned int i = 0; i < sentPackets.size(); i++) {

		if (sentPackets[i].xid == ntohl(dhcpHeader->xid)) { //found corresponding discovery packet

			if (sentPackets[i].confirmed == true || sentPackets[i].address != 0) {
				//fprintf(stderr, "duplicate offer\n");
				return -2;
			}

			threadAccess.lock();
			sentPackets[i].address = ntohl(dhcpHeader->yiaddr);
			sentPackets[i].serverID = *serverID;
			threadAccess.unlock();

			PacketCreator newPacket(DHCP_REQUEST, &(sentPackets[i]), NULL, serverID);
			int size = newPacket.fillPacket();
			char *packet = newPacket.getPacket();

			int sent = pcap_inject(handle, packet, size);
			if (sent <= 0)
				fprintf(stderr, "Error sending request packet\n");

			return 0;
		}
	}
	return -1;
}

//if ACK packet arrives, confirms its legitimacy
int confirmAck(struct dhcphdr *dhcpHeader, struct ip *ipHeader, struct ethhdr *ethHeader) {

	for (unsigned int i = 0; i < sentPackets.size(); i++) {
		if (sentPackets[i].xid == ntohl(dhcpHeader->xid)) {

			if (sentPackets[i].confirmed == false) {
			std::cout << "successfully reserved IP: " << (int)(uint8_t)(sentPackets[i].address >> 24) << "."
			 << (int)(uint8_t)(sentPackets[i].address >> 16) << "." << (int)(uint8_t)(sentPackets[i].address >> 8) << "."
			  << (int)(uint8_t)(sentPackets[i].address) << "\n";

			 } else {
			 	std::cout << "successfully renewed/rebinded IP: " << (int)(uint8_t)(sentPackets[i].address >> 24) << "."
			 << (int)(uint8_t)(sentPackets[i].address >> 16) << "." << (int)(uint8_t)(sentPackets[i].address >> 8) << "."
			  << (int)(uint8_t)(sentPackets[i].address) << "\n";
			 }
			bool givenTimeRenew, givenTimeRebind, givenTimeLease = false;

			threadAccess.lock();
			sentPackets[i].confirmed = true;
			threadAccess.unlock();

			int position = 0;
			while (true) { //checks packet options for renewal time, rebinding time and lease time

				if (dhcpHeader->options[position] == RENEWAL_TIME) { 
					position += 2;
					givenTimeRenew = true;
					uint32_t time = ntohl(*((uint32_t *)(&(dhcpHeader->options[position]))));
					position += 4;
					sentPackets[i].renewalTime = time;
				} else if (dhcpHeader->options[position] == REBINDING_TIME) {
					position += 2;
					givenTimeRebind = true;
					uint32_t time = ntohl(*((uint32_t *)(&(dhcpHeader->options[position]))));
					position += 4;
					sentPackets[i].rebindingTime = time;
				} else if (dhcpHeader->options[position] == LEASE_TIME) {
					position += 2;
					givenTimeLease = true;
					uint32_t time = ntohl(*((uint32_t *)(&(dhcpHeader->options[position]))));
					position += 4;
					sentPackets[i].leaseTime = time;
				} else if (dhcpHeader->options[position] == OPTIONS_END) {
					break;
				} else { //skip option

					position++;
					position += dhcpHeader->options[position];
					position++;
				}
			}

			if (!givenTimeLease) {
				fprintf(stderr, "Lease time not given (weird)\n");
				return -1;
			}

			if (!givenTimeRenew || !givenTimeRebind) {
				sentPackets[i].renewalTime = (int)sentPackets[i].leaseTime*0.5;
				sentPackets[i].rebindingTime = (int)sentPackets[i].leaseTime*0.875;
			}

			threadAccess.lock();
			memcpy(sentPackets[i].serverMac, ethHeader->source, 6);
			sentPackets[i].taken = false;
			sentPackets[i].unixTime = time(NULL);
			sentPackets[i].serverAddress = ntohl(ipHeader->ip_src.s_addr);
			threadAccess.unlock();

			std::thread renewTimer(&renewIP, &(sentPackets[i])); //thread that activates and attempts to extend lease duration
			renewTimer.detach();

			return 0;

		}
	}
	return -1;
}

void socketClientListener() {

	struct sockaddr_in myAddress, otherAddress;
	uint32_t serverID;
     
    unsigned int slen = sizeof(otherAddress) , recv_len;
    char buf[BUFLEN];
     
    if ((socketClient=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) 
        return;
    
    memset((char *) &myAddress, 0, sizeof(myAddress));

    myAddress.sin_family = AF_INET;
    myAddress.sin_port = htons(CLIENT_PORT);
    myAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    if( bind(socketClient , (struct sockaddr*)&myAddress, sizeof(myAddress)) == -1)
        return;

    while(true) {  
        if ((recv_len = recvfrom(socketClient, buf, BUFLEN, 0, (struct sockaddr *) &otherAddress, &slen)) == -1)
            return;      
    }

}
