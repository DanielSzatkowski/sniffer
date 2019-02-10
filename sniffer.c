#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>

/*******************************************************/
/* STRUKTURY PROTOKOLOW DLA KTORYCH NIE BYLO BIBLIOTEK */
/*******************************************************/

/*struktura protokolu DHCP (zrodlo ponizej)*/
/**http://dox.ipxe.org/include_2ipxe_2dhcp_8h_source.html**/
struct dhcphdr {
        /** Operation
         *
         * This must be either @c BOOTP_REQUEST or @c BOOTP_REPLY.
         */
        uint8_t op;
        /** Hardware address type
         *
         * This is an ARPHRD_XXX constant.  Note that ARPHRD_XXX
         * constants are nominally 16 bits wide; this could be
         * considered to be a bug in the BOOTP/DHCP specification.
         */
        uint8_t htype;
        /** Hardware address length */
        uint8_t hlen;
        /** Number of hops from server */
        uint8_t hops;
        /** Transaction ID */
        uint32_t xid;
        /** Seconds since start of acquisition */
        uint16_t secs;
        /** Flags */
        uint16_t flags;
        /** "Client" IP address
         *
         * This is filled in if the client already has an IP address
         * assigned and can respond to ARP requests.
         */
        struct in_addr ciaddr;
        /** "Your" IP address
         *
         * This is the IP address assigned by the server to the client.
         */
        struct in_addr yiaddr;
        /** "Server" IP address
         *
         * This is the IP address of the next server to be used in the
         * boot process.
         */
        struct in_addr siaddr;
        /** "Gateway" IP address
         *
         * This is the IP address of the DHCP relay agent, if any.
         */
        struct in_addr giaddr;
        /** Client hardware address */
        uint8_t chaddr[16];
        /** Server host name (null terminated)
         *
         * This field may be overridden and contain DHCP options
         */
        char sname[64];
        /** Boot file name (null terminated)
         *
         * This field may be overridden and contain DHCP options
         */
        char file[128];
        /** DHCP magic cookie
         *
         * Must have the value @c DHCP_MAGIC_COOKIE.
         */
        uint32_t magic;
        /** DHCP options
         *
         * Variable length; extends to the end of the packet.  Minimum
         * length (for the sake of sanity) is 1, to allow for a single
         * @c DHCP_END tag.
         */
        uint8_t options[0];
};

/*struktura protokolu RIP*/
struct riphdr{
	unsigned char 	command;
	unsigned char 	version;
	unsigned short 	zero1;
	unsigned short 	family;
	unsigned short 	zero2;
	uint32_t	ipAddress;
	unsigned int 	zero3;
	unsigned int	zero4;
	unsigned int 	metric;
};

void error(char *txt)
{
	perror(txt);

	exit(1);
}

/************************************************************/
/*         FUNKCJE WYSWIETLAJACE NAGLOWKI PROTOKOLOW        */
/************************************************************/
void printARP(unsigned char *buffer)
{
	struct ether_arp *arp_header;
	int i;

	arp_header = (struct ether_arp*) (buffer + sizeof(struct ether_header));

	/*********************************/
	/*wypisywaine danych ze structury*/
	/*********************************/
	printf("Naglowek protokolu ARP: \n");

	/*Dane wysylajacego*/
	printf("Adres IP wysylajacego: ");
	for(i = 0; i < 4; i++){
		printf("%d", arp_header -> arp_spa[i]);

		if(i != 3){
			printf(".");
		}
	}
	printf("\n");

	printf("Adres MAC wysylajacego: ");
	for(i = 0; i < 6; i++){
		printf("%02X", arp_header -> arp_sha[i]);
		if(i != 5){
			printf(":");
		}
	}
	printf("\n");

	/*Dane odbierajacego*/
	printf("Adres IP jednostki do ktorej wysylana jest wiadomosc: ");
	for(i = 0; i < 4; i++){
		for(i = 0; i < 4; i++){
			printf("%d", arp_header -> arp_tpa[i]);

			if(i != 3){
				printf(".");
			}
		}
	}
	printf("\n");

	printf("Adres MAC jednostki do ktorej wysylana jest wiadomosc");
	for(i = 0; i < 6; i++){
		printf("%02X", arp_header -> arp_tha[i]);
		if(i != 5){
			printf(":");
		}
	}
	printf("\n\n");
}

void printEthernet(struct ether_header * ether_header)
{
	int i;

	printf("Protokol ethernet: \n");

	printf("Adres MAC jednostki do ktorej wysylana jest wiadomosc: ");
	for(i = 0; i < 6; i++){
		printf("%02X", ether_header -> ether_dhost[i]);
		if(i != 5){
			printf(":");
		}
	}
	printf("\n");

	printf("Adres MAC jednostki z ktorej wysylana jest wiadomosc: ");
	for(i = 0; i < 6; i++){
		printf("%02X", ether_header -> ether_shost[i]);
		if(i != 5){
			printf(":");
		}
	}
	printf("\n\n");
}

void printTCP(unsigned char *buffer, unsigned short length)
{
	struct tcphdr *tcp_h;
	tcp_h = (struct tcphdr *)(buffer+ length + sizeof(struct ether_header));

	printf("Naglowek TCP:\n");
	printf("Port odbiorcy: %d\n", ntohs(tcp_h -> th_dport));
	printf("Port nadawcy: %d\n", ntohs(tcp_h -> th_sport));
	printf("Numer sekwencji: %u\n", ntohl(tcp_h -> th_seq));
	printf("Acknowledgement number: %u \n", ntohl(tcp_h -> th_ack));
	printf("Suma kontrolna: %d\n", ntohs(tcp_h -> th_sum));
	printf("Flaga pilnosci: %d\n", ntohs(tcp_h -> th_urp));
	printf("\n");


	/*****************HTTP************************/
	/*tylko serwer uzywa portu 80 do komunikacji - wysylania http*/
	if(ntohs(tcp_h -> th_dport) == 80){
		printf("WYSLANO PAKIET - PROTOKOL HTTP\n\n");
	} else if(ntohs(tcp_h -> th_sport) == 80){
		printf("OTRZYMANO PAKIET - PROTOKOL HTTP\n\n");
	}
}

void printICMP(unsigned char *buffer, unsigned short length)
{
	struct icmphdr *icmph;
	icmph = (struct icmphdr *)(buffer + length + sizeof(struct ether_header));

	/*zamiana adresu na adres ktory wygodnie mozna przeczytac*/
	char address[INET_ADDRSTRLEN];
	uint32_t gatewayAddress = (icmph -> un).gateway;
	inet_ntop(AF_INET, &gatewayAddress, address, INET_ADDRSTRLEN);

	printf("Protokol ICMP: \n");
	printf("Typ wiadomosci: %d \n", ntohs(icmph -> type));
	printf("id: %d\n", ntohs((icmph -> un).echo.id));
	printf("sequence: %u\n", ntohl((icmph -> un).echo.sequence));
	printf("adres bramy: %s\n", address);
	printf("\n");
}

void printICMPv6(unsigned char *buffer, unsigned short length)
{
	struct icmp6_hdr *icmph;
	icmph = (struct icmp6_hdr *)(buffer + length + sizeof(struct ether_header));

	printf("Protokol ICMPv6: \n");
	printf("Typ: %u\n", ntohs(icmph -> icmp6_type));
	printf("Code: %u\n", ntohs(icmph -> icmp6_code));
	printf("Suma kontrolna: %u\n", ntohs(icmph -> icmp6_cksum));
	printf("\n");
}

void printDHCP(unsigned char *buffer, unsigned short ipLen, unsigned int udpLen)
{
	struct dhcphdr *dhcp;
	dhcp = (struct dhcphdr *)(buffer + ipLen + udpLen + sizeof(struct ethhdr));

	printf("Operacja: %d\n", dhcp -> op);
	printf("Typ adresu fizycznego: %d\n", ntohs(dhcp -> htype));
	printf("Dlugosc adresu fizycznego: %d\n", ntohs(dhcp -> hlen));
	printf("Liczba \"hops\": %d\n", ntohs(dhcp -> hops));

	/*zamiana adresow znajdujacego sie w strukturze na takie ktore mozna wygodnie czytac*/	
	char address[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(dhcp->ciaddr), address, INET_ADDRSTRLEN);
	printf("IP klienta: %s\n", address);

	inet_ntop(AF_INET, &(dhcp->yiaddr), address, INET_ADDRSTRLEN);
	printf("IP ktore serwer przypisuje klientowi: %s\n", address);

	inet_ntop(AF_INET, &(dhcp->siaddr), address, INET_ADDRSTRLEN);
	printf("IP Serwera: %s\n", address);

	inet_ntop(AF_INET, &(dhcp->siaddr), address, INET_ADDRSTRLEN);
	printf("IP Bramy: %s\n", address);

	printf("\n");
}

void printRIP(unsigned char *buffer, int ipLen, int udpLen)
{
	struct riphdr *riph;
	riph = (struct riphdr *)(buffer + ipLen + udpLen);
	char address[INET_ADDRSTRLEN];

	/*zamiana adresu wpisanego do struktury na taki ktory wygodnie czyta sie czlowiekowi*/
	inet_ntop(AF_INET, &(riph -> ipAddress), address, INET_ADDRSTRLEN);

	printf("Protokol RIP:\n");
	printf("Polecenie: %u\n", riph -> command);
	printf("Wersja: %u\n", riph -> version);
	printf("Metryka: %u\n", riph -> metric);
	printf("Adres: %s\n", address);

	printf("\n");
}

void printUDP(unsigned char *buffer, unsigned short length)
{
	struct udphdr *udph;
	udph = (struct udphdr *)(buffer + length + sizeof(struct ether_header));

	printf("Protokol UDP:\n");
	printf("Port nadawcy: %d\n", ntohs(udph -> uh_sport));
	printf("Port odbiorcy: %d\n", ntohs(udph -> uh_dport));
	printf("Dlugosc UDP: %d\n", ntohs(udph -> uh_ulen));
	printf("Suma kontrolna: %d\n", ntohs(udph -> uh_sum));
	printf("\n");

	if(ntohs(udph -> dest) == 67){		/* DHCP 67 - klient -> serwer, 68 serwer -> klient*/
		printf("Protokol DHCP - klient-serwer:\n");
		printDHCP(buffer, length, sizeof(struct udphdr));
	} else if(ntohs(udph -> dest) == 68){
		printf("Protokol DHCP - serwer-klient:\n");
		printDHCP(buffer, length, sizeof(struct udphdr));
	} else if(ntohs(udph -> source) == 520 || ntohs(udph -> dest) == 520){ /*RIP*/
		printRIP(buffer, length, sizeof(struct udphdr));
	}
}

void printIPv4(unsigned char*buffer)
{
	struct ip *ip4_header;
	ip4_header = (struct ip*)(buffer + sizeof(struct ether_header));

	/*zamiana adresow ze struktur tak aby byly czytelne dla czlowieka*/
	char adresDoc[INET_ADDRSTRLEN];
	char adresNad[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip4_header -> ip_src), adresNad, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip4_header -> ip_dst), adresDoc, INET_ADDRSTRLEN);

	printf("Naglowek IPv4\n");
	printf("Wersja: %d\n", ip4_header -> ip_v);
	printf("TTL: %d\n", ip4_header -> ip_ttl);
	printf("Suma kontrolna: %d \n", ip4_header -> ip_sum);
	printf("Adres docelowy: %s \n", adresDoc);
	printf("Adres nadawcy: %s \n", adresNad);

	printf("\n");

	/*rozpoznaje protokol wyzszej warstwy*/
	switch(ip4_header -> ip_p){
		case 1:
			printICMP(buffer, (ip4_header -> ip_hl) * 4);
			break;
		case 6:
			printTCP(buffer, (ip4_header -> ip_hl) * 4); /*dlugosc naglowka*/
			break;
		case 17:
			printUDP(buffer, (ip4_header -> ip_hl) * 4);
			break;
	}
}

void printIPv6(unsigned char* buffer)
{
	struct ip6_hdr *ip6_header;
	ip6_header = (struct ip6_hdr*)(buffer + sizeof(struct ether_header));

	printf("Naglowek IPv6:\n");

	char address[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &(ip6_header->ip6_src), address, INET6_ADDRSTRLEN);
	printf("Adres nadawcy: %s\n", address);

	inet_ntop(AF_INET6, &(ip6_header->ip6_dst), address, INET6_ADDRSTRLEN);
	printf("Adres odbiorcy: %s\n", address);
	printf("Nastepny protokol(wyzsza warstwa): %d\n", ip6_header -> ip6_ctlun.ip6_un1.ip6_un1_nxt);
	printf("Hop limit: %d\n", ip6_header -> ip6_ctlun.ip6_un1.ip6_un1_hlim);
	printf("Wielkosc payload: %d\n", ntohs(ip6_header -> ip6_ctlun.ip6_un1.ip6_un1_plen));
	printf("\n");

	/*rozpoznanie protokolu wyzszej warstwy*/
	switch(ip6_header -> ip6_ctlun.ip6_un1.ip6_un1_nxt){
		case 1:
			printICMP(buffer, sizeof(struct ip6_hdr));
			break;
		case 6:
			printTCP(buffer, sizeof(struct ip6_hdr));
			break;
		case 17:
			printUDP(buffer, sizeof(struct ip6_hdr));
			break;
	}
}

/*******************************************************/
/*    rozpoznawanie jaki pakiet zostal przechwycony    */
/*******************************************************/
void identifyProtocols(unsigned char* buffer, ssize_t data_size)
{
	/*zapisywanie naglowka ethernetowego pakeitu*/
	struct ether_header *ether_header;			/*struktura naglowka protokolu ethernet*/
	ether_header = (struct ether_header*)buffer;
	printEthernet(ether_header);				/*wyswietl dane znajdujace sie w ethernet*/


	/*rozpoznanie protokolu z warstwy wyzej*/
	if(ntohs(ether_header -> ether_type) == 0x0806){		/*ARP*/
		printARP(buffer);	
	} else if(ntohs(ether_header -> ether_type) == 0x0800){		/*IPv4*/
		/*ta funkcja wypisze naglowek IPv4*/
		printIPv4(buffer);	
	} else if(ntohs(ether_header -> ether_type) == 0x86DD){		/*IPv6*/
		/*ta funkcja wypisze naglowek IPv6*/
		printIPv6(buffer);
	}
}


/*************************************************************/
/*                        FUNKCJA MAIN                       */
/*************************************************************/
int main(int argc, char *argv[])
{
	int 		sd; 					/*deskryptor dla gniazda*/
	struct ifreq 	ifr;					/*struktura sluzaca do konfiguracji interface'ow*/
	struct sockaddr saddr;
	socklen_t 	saddr_size = sizeof(saddr);
	ssize_t 	data_size;

	unsigned char* buffer = (unsigned char*)malloc(65536);

	/*tworzenie deskryptora dla gniazda*/
	if((sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		error("Blad - funkcja socket()");

	/*przelaczanie interfejsu sieciowego w tryb promisc*/
	strncpy((char *)ifr.ifr_name, argv[1], IF_NAMESIZE);   	/*zapisuje nazwe interface'u do struktury ifr*/

	/*nasluchuje ruch sieciowy*/
	while(1){
		if((data_size = recvfrom(sd, buffer, 65536, 0, &saddr, &saddr_size)) == -1)
			error("Blad funkcji recvfrom");

		/*rozpoznawanie i wypisywanie naglowka pakietu*/
		identifyProtocols(buffer, data_size);
	}

	close(sd);
	free(buffer);

	return 0;
}
