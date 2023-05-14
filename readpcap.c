#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SIZE_ETHERNET 14


#define TCP_HLEN(tcp) (((tcp)->th_off & 0xf0) >> 2)
#define IP_HL(ip)  (((ip)->ip_hl) & 0x0f)
#define IP_V(ip)   (((ip)->ip_hl) >> 4)

int Hex2Dex(int num1,int num2){
	int sum = 0;
	sum = (num1 % 16) * 16 * 16 + (num1 / 16) * 16 * 16 * 16 + num2;
	return sum;
}

void http_parsing(u_char *payload, int size_payload){
	int flag = 0;
	int printlen = 0;
	for(int i = 0; i < size_payload; i++ ){
		if(i + 3 < size_payload && payload[i] == 0x0d && payload[i+1] == 0x0a && 
		   payload[i+2] == 0x0d && payload[i+3] == 0x0a){
			flag = 1;
			break;
		}
		printlen += 1;
	}
	if(flag == 0){
		printf("  Data: ......\n");
	}else{
		printf("  ");
		for(int i = 0; i < printlen; i++){
			printf("%c", payload[i]);
			if(i > 0 && payload[i - 1] == 0x0d && payload[i] == 0x0a) printf("  ");
		} 
		printf("\n");
	}
}

void ssl_tls_parsing(u_char *payload, int size_payload){
	int session_id_length = 0;
	int idx = 0;
	int compression_methods_length = 0;
	int cipher_suites_length = 0;
	int extension_length = 0;
	if(payload[0] == 0x16){
		printf("  Content Type: Handshake\n");
		printf("  Version: ");
		if(payload[1] == 0x03 && payload[2] == 0x01){
			printf("TLS 1.0\n");
		}else if(payload[1] == 0x03 && payload[2] == 0x02){
			printf("TLS 1.1\n");
		}else if(payload[1] == 0x03 && payload[2] == 0x03){
			printf("TLS 1.2\n");
		}
		
		if(payload[5] == 0x01){
			printf("    Handshake Type: Client Hello\n");
			printf("    Version: ");
			if(payload[9] == 0x03 && payload[10] == 0x01){
                printf("TLS 1.0\n");
            }else if(payload[9] == 0x03 && payload[10] == 0x02){
                printf("TLS 1.1\n");
            }else if(payload[9] == 0x03 && payload[10] == 0x03){
                printf("TLS 1.2\n");
            }
			printf("    Random: ");
			for(int i = 11; i < 43; i++){
				printf("%x", payload[i]);
			}
			idx = 43;
			printf("\n");
			session_id_length = (int)payload[idx];
			printf("    Session ID Length: %d\n", session_id_length);
			idx += 1;
			if(session_id_length != 0){
				printf("    Session ID: ");
				for(int i = idx; i < idx + session_id_length; i++){
					printf("%x", payload[i]);
				}
				printf("\n");
			}
			idx +=  session_id_length + 1;
			cipher_suites_length = (int)payload[idx];
			printf("    Cipher Suites Length: %d\n", cipher_suites_length);
			printf("    Cipher Suites: ");
			for(int i= idx +1; i < idx + 1 + cipher_suites_length; i++){
				printf("%02x", payload[i]);
				if( (i - idx) % 2 == 0) printf(" ");
			}
		    printf("\n");
			idx = idx + 1 + cipher_suites_length;
			compression_methods_length = (int)payload[idx];
			printf("    Compression Methods Length: %d\n", compression_methods_length);
			printf("    Compression Methods: ");
			for(int i = idx + 1; i < idx + compression_methods_length +1; i++){
				printf("%02x ", payload[i]);
			}
			printf("\n");
			idx += compression_methods_length + 1;
		    int num1 = (int)payload[idx];
			int num2 = (int)payload[idx + 1];
			extension_length = Hex2Dex(num1, num2);
			printf("    Extensions Length: %d\n", extension_length);
			num1 = (int)payload[idx + 9], num2 = (int)payload[idx + 10];
			int server_name_length = Hex2Dex(num1, num2);
			printf("      Server Name length: %d\n", server_name_length);
			idx += 11;
			printf("      Server Name: ");
			for(int i = idx; i < idx + server_name_length + 1; i++){
				printf("%c", payload[i]);
			}
			printf("\n");
			
		}
		else if(payload[5] == 0x02){
			printf("    Handshake Type: Server Hello\n");
			printf("    Version: ");
			if(payload[9] == 0x03 && payload[10] == 0x01){
                printf("TLS 1.0\n");
            }else if(payload[9] == 0x03 && payload[10] == 0x02){
                printf("TLS 1.1\n");
            }else if(payload[9] == 0x03 && payload[10] == 0x03){
                printf("TLS 1.2\n");
            }
			printf("    Random: ");
			for(int i = 11; i < 43; i++){
				printf("%x", payload[i]);
            }
            printf("\n");
			idx = 43;
            session_id_length = (int)payload[idx];
			idx += 1;
			printf("    Session ID Length: %d\n", session_id_length);
			if(session_id_length != 0 ){
				printf("    Session ID: ");
				for(int i = idx; i < idx + session_id_length; i++)
				{
					printf("%x", payload[i]);
				}
				printf("\n");
			}
			idx += session_id_length;
			printf("    Cipher Suites: ");
			for(int i = idx; i < idx + 2; i++){
				printf("%02x", payload[i]);
			}
			printf("\n");
			idx += 2;
			printf("    Compression Methods: %02x\n", payload[idx]);
			idx += 1;
			int num1 = (int)payload[idx];
			int num2 = (int)payload[idx + 1];
			extension_length = Hex2Dex(num1, num2);
			printf("    Extensions Length: %d\n", extension_length);
			
		}
		else if(payload[5] == 0x0b){
			printf("    Handshake Type: Certificate\n");
			printf("  signedCertificate:\n");
			int serival_number_length = (int)payload[29];
			printf("    serivalNumber: ");
			idx = 30;
			for(int i = idx; i < 30 + serival_number_length; i++){
				printf("%x", payload[i]);
			}
			printf("\n");
		}else if(payload[5] == 0x10){
			printf("    Handshake Type: Client Key Exchange\n");
			int pubkey_length = (int)payload[9];
			printf("    Pubkey: ");
			for(int i = 10; i < 10 + pubkey_length; i++){
				printf("%02x", payload[i]);
			}
			printf("\n");
		}
	}else if(payload[0] == 0x15){
		printf("  Content Type: Encrypted Alert\n");
		printf("  Version: ");
		if(payload[1] == 0x03 && payload[2] == 0x01){
			printf("TLS 1.0\n");
		}else if(payload[1] == 0x03 && payload[2] == 0x02){
			printf("TLS 1.1\n");
		}else if(payload[1] == 0x03 && payload[2] == 0x03){
			printf("TLS 1.2\n");
		}
	}else if(payload[0] == 0x17){
		printf("  Content Type: Application Data\n");
		printf("  Version: ");
		if(payload[1] == 0x03 && payload[2] == 0x01){
			printf("TLS 1.0\n");
        }else if(payload[1] == 0x03 && payload[2] == 0x02){
			printf("TLS 1.1\n");
        }else if(payload[1] == 0x03 && payload[2] == 0x03){
			printf("TLS 1.2\n");
		}
	}else if(payload[0] == 0x14){
		printf("  Content Type: Change Cipher Spec\n");
		printf("  Version: ");
		if(payload[1] == 0x03 && payload[2] == 0x01){
			printf("TLS 1.0\n");
		}else if(payload[1] == 0x03 && payload[2] == 0x02){
			printf("TLS 1.1\n");
		}else if(payload[1] == 0x03 && payload[2] == 0x03){
			printf("TLS 1.2\n");
		}
	}
}

void dns_parsing(u_char *payload, int size_payload){
	 int questions = 0, answer_rrs = 0, authority_rrs = 0, additional_rrs = 0;
	 printf("  Transaction ID: 0x%02x%02x\n", payload[0], payload[1]);
	 printf("  Flags: 0x%02x%02x ", payload[2], payload[3]);
	 int idx = 13;
	 if(payload[2] == 0x01 && payload[3] == 0x00){
		printf("Standard query\n");
	 }else if(payload[2] == 0x81 && payload[3] == 0x80){
		printf("Standard query response, No error\n");
	 }else if(payload[2] == 0x81 && payload[3] == 0x03){
		printf("Standard query response, No such name\n");
	 }
	 questions = (int)payload[5];
	 answer_rrs = (int)payload[7];
	 authority_rrs = (int)payload[9];
	 additional_rrs = (int)payload[11];;
	 printf("  Question: %d\n", questions);
	 printf("  Answer RRs: %d\n", answer_rrs);
	 printf("  Authority RRs: %d\n", authority_rrs);
	 printf("  Additional RRs: %d\n", additional_rrs);
	 printf("  Queries:\n");
	 printf("    Name: ");
	 while(payload[idx] != 0x00){
		if((int)payload[idx] >= 32)
			printf("%c", payload[idx]);
		else
			printf(".");
		idx += 1;
	 }
	 printf("\n    Type: ");
	 idx += 2;
	 if(payload[idx] == 0x01){
		printf("A\n");
	 }else if(payload[idx] == 0x1c){
		printf("AAAA\n");
	 }else if(payload[idx] == 0x05){
		printf("CNAME\n");
	 }
	 idx += 1;
	 printf("    Class: ");
	 printf("0x%02x%02x\n", payload[idx], payload[idx + 1]);
	 if(payload[2] == 0x81 && payload[3] == 0x80){
		idx += 2;
		int first_idx;
		printf("  Answer:\n");
		while(idx < size_payload){
			printf("    Type: ");
			if(payload[idx + 3] == 0x05){
				printf("CNAME, ");
				for(idx = idx + 13; payload[idx] != 0xc0 &&  idx < size_payload; idx++){
					if((int)payload[idx] > 32){
						printf("%c", payload[idx]);
					}else{
						printf(".");
					}
				}
				if(payload[idx-1] != 0x00) idx += 2;
				printf("\n");
			}else if(payload[idx + 3] == 0x01){
				printf("A, ");
				first_idx = idx + 12;
				for(idx = idx + 12; payload[idx] != 0xc0 && idx < size_payload; idx++)
				{	
					if(first_idx != idx) printf(".%d", payload[idx]);
					else printf("%d", payload[idx]);
				}
					printf("\n");
			}else if(payload[idx + 3] == 0x1c){
				printf("AAAA, ");
				int cnt = 0;
				first_idx = idx + 12;
				for(idx = idx + 12; payload[idx] != 0xc0 && idx < size_payload; idx++)
				{
					cnt++;
					if(cnt % 2 == 1 && idx != first_idx)
                        printf(":%02x", payload[idx]);
					else
						printf("%02x", payload[idx]);
				}
					printf("\n");
			}else{
				printf("Authoritative nameservers\n");
				break;
			}
		}
	 }
}

void packetHandler(u_char *userdata, const struct pcap_pkthdr * pkthdr, const u_char *packet){
	static int cnt = 1;
	printf("**************** Packet: %d ***************\n",cnt);
	cnt++;
	const struct ether_header* ethernetHeader;
	const struct ip* ipHeader;
	const struct tcphdr* tcp;
	const struct udphdr* udp;
	const struct icmphdr* icmp;
	u_char *payload;

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;
	ethernetHeader = (struct ether_header*) packet;
	if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP){
		struct ether_arp* arp;
		arp = (struct ether_arp*)(packet + SIZE_ETHERNET);
		printf("ARP packet\n");
		printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
			   arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], 
			   arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5],
			   arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
			   arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
		printf("IP Address: %s -> %s\n", inet_ntoa(*(struct in_addr *)arp->arp_spa), 
			   inet_ntoa(*(struct in_addr *)arp->arp_tpa));
		return;
	}
	ipHeader =(struct ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ipHeader) * 4;
	if(size_ip < 20){ 
		printf("Invalid Ip Header Length: %d bytes\n", size_ip);
		return;
	}
	// print source and destination IP address
	printf("IP Address: %s -> ", inet_ntoa(ipHeader->ip_src));
	printf("%s\n", inet_ntoa(ipHeader->ip_dst));
	int protocol_num= ipHeader->ip_p;

	switch(protocol_num){
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
			break;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			break;
		case IPPROTO_IP:
			printf("Protocol: IP\n");
			return;
		default:
			printf("Protocol: unknown\n");
			return;
	}
	
	if(protocol_num == IPPROTO_TCP){
		tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = tcp->doff * 4;
		if(size_tcp < 20){
			printf("Invalid TCP Header Length: %d bytes\n", size_tcp);
			return;
		}
		int sport = ntohs(tcp->th_sport);
		int dport = ntohs(tcp->th_dport);
		printf("Source Port: %d, Destionation Port: %d\n", sport, dport);
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		size_payload = ntohs(ipHeader->ip_len) - (size_ip + size_tcp);
		if(size_payload > 0){
			printf("Size Payload: %d\n", size_payload);
			if((sport == 80) || (dport == 80)){
				printf("---- HTTP parsing ----\n");
			    http_parsing(payload, size_payload);
			}
			if((sport == 443 || dport == 443)){
			    printf("---- SSL/TLS parsing ----\n");
			    ssl_tls_parsing(payload, size_payload);
			}
		}
	}
	else if(protocol_num == IPPROTO_UDP){
		udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
		size_udp = 8;
		int sport = ntohs(udp->uh_sport);
		int dport = ntohs(udp->uh_dport);
		printf("Source Port: %d, Destionation Port: %d\n", sport, dport);
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
		size_payload = ntohs(ipHeader->ip_len) - (size_ip + size_udp);
		if(size_payload > 0){
			printf("Size Payload: %d\n", size_payload);
			if( (sport == 53) || (dport == 53)){
				printf("---- DNS parsing ----\n");
				dns_parsing(payload, size_payload);
			}
		}

	}else if(protocol_num == IPPROTO_ICMP){
		icmp = (struct icmphdr*)(packet + SIZE_ETHERNET + size_ip);
		printf("Type: %d, ", icmp->type);
		if(icmp->type == 0 && icmp->code== 0){
			printf("Echo Reply (ping)\n");
		}else if(icmp->type == 3 && icmp->code== 1){
			printf("Host Unreachable\n");
		}else if(icmp->type == 3 && icmp->code== 3){
			printf("Port Unreachable\n");
		}else if(icmp->type == 8 && icmp->code==0){
			printf("Echo Request (ping)\n");
		}else{
			printf("Unknown\n");
		}
		printf("Code: %d\n", icmp->code);
		printf("Chencksum: %d\n", icmp->checksum);
		if(icmp->type == ICMP_ECHO){
			int identifier = ntohs(*(uint16_t*)(packet + SIZE_ETHERNET + size_ip + sizeof(struct icmphdr) - 4));
			int sequence_number = ntohs(*(uint16_t*)(packet + SIZE_ETHERNET + size_ip + sizeof(struct icmphdr) - 2));
			printf("Identifier: %d\n", identifier);
			printf("Sequence Number: %d\n", sequence_number);

		}
	}
	printf("\n");
}

int main(){
	char errbuf[100];
	pcap_t *handle = pcap_open_offline("test.pcap", errbuf);
	if(handle == NULL){
		printf("%s\n", errbuf);
		exit(0);
	}
	pcap_loop(handle, -1, packetHandler, NULL);
	
	return 0;
}
