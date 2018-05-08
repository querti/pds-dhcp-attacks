all:
	g++ -std=c++11 -Wno-int-to-pointer-cast common.cpp pds-dhcpstarve.cpp -o pds-dhcpstarve -lpcap -pthread
	g++ -std=c++11 -Wno-int-to-pointer-cast common.cpp pds-dhcprogue.cpp -o pds-dhcprogue -lpcap -pthread
