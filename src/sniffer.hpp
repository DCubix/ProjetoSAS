#ifndef SNIFFER_HPP
#define SNIFFER_HPP

#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <functional>

#ifdef _WIN32
#include <stdio.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#define errcode WSAGetLastError()
#define INVALID_SOCK (SOCKET)(~0)
#else
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>

typedef int SOCKET;
#define errcode errno
#define INVALID_SOCK -1
#endif

#include "headers.hpp"

using SocketAddressIn = struct sockaddr_in;
using SocketAddress = struct sockaddr;
using HostEnt = struct hostent;

struct Packet {
	std::string from, to, type;
	std::vector<char> data;
};

class Sniffer {
public:
	inline virtual ~Sniffer() = default;

	inline Sniffer() {
#ifdef _WIN32
		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
			std::cerr << __LINE__ <<  " - WSAStartup() falhou: " << WSAGetLastError() << std::endl;
			return;
		}
#endif
		m_interfaces.clear();
		m_interfaceNames.clear();

		createSocket();

#ifdef _WIN32
		char hostName[1024];
		if ((gethostname(hostName, 1024)) == -1) {
			std::cout << __LINE__ <<  " - Erro: " << errcode << std::endl;
			return;
		}

		if ((m_host = gethostbyname(hostName)) == NULL) {
			std::cout << __LINE__ <<  " - Erro: " << errcode << std::endl;
			return;
		}

		struct in_addr addr;
		for (int i = 0; m_host->h_addr_list[i] != 0; ++i) {
			memcpy(&addr, m_host->h_addr_list[i], sizeof(struct in_addr));
			std::cout << "\tN: " << i << " - End.: " << inet_ntoa(addr) << std::endl;
			m_interfaceNames.push_back(std::string(inet_ntoa(addr)));
		}
#else
		struct ifaddrs *addrs, *tmp;
		getifaddrs(&addrs);
		tmp = addrs;

		int i = 0;
		while (tmp) {
			if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET) {
				std::cout << "\tN: " << i << " - Nome.: " << tmp->ifa_name << std::endl;
				m_interfaceNames.push_back(std::string(tmp->ifa_name));
			}
			tmp = tmp->ifa_next;
			i++;
		}

		freeifaddrs(addrs);
#endif
	}

	inline void start(int in) {
		if (m_socket == INVALID_SOCK) {
			createSocket();
		}

#ifdef _WIN32
		memset(&m_dest, 0, sizeof(SocketAddressIn));
		memcpy(&m_dest.sin_addr.s_addr, m_host->h_addr_list[in], sizeof(m_dest.sin_addr.s_addr));
		m_dest.sin_family = AF_INET;
		m_dest.sin_port = 0;

		if (::bind(m_socket, (SocketAddress*)&m_dest, sizeof(m_dest)) != 0) {
			std::cout << __LINE__ <<  " - Erro: " << errcode << std::endl;
			return;
		}

		// Modo promíscuo
		int j = 1;
		if (WSAIoctl(m_socket, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in, 0, 0) == SOCKET_ERROR) {
			std::cout << __LINE__ <<  " - Erro: " << errcode << std::endl;
			return;
		}
#else
		struct ifreq ifopts;
		struct ifreq if_ip;

		// Modo Promíscuo
		memcpy(ifopts.ifr_ifrn.ifrn_name, m_interfaceNames[in].c_str(), IFNAMSIZ-1);
		ioctl(m_socket, SIOCGIFFLAGS, &ifopts);
		ifopts.ifr_flags |= IFF_PROMISC;
		ioctl(m_socket, SIOCSIFFLAGS, &ifopts);

		if (setsockopt(m_socket, SOL_SOCKET, SO_BINDTODEVICE, m_interfaceNames[in].c_str(), IFNAMSIZ-1) == -1)	{
			std::cout << __LINE__ <<  " - Erro: " << errcode << std::endl;
			close(m_socket);
			return;
		}
#endif

		m_sniffing = true;
		m_stopped = false;

		std::thread(&Sniffer::sniffLoop, this).detach();
	}

	inline void stop() {
		m_lock.lock();
		m_sniffing = false;
		m_lock.unlock();
	}

	inline std::vector<std::string>& interfaceNames() { return m_interfaceNames; }
	inline bool stopped() const { return m_stopped; }

	inline void onPacketArrival(const std::function<void(Packet)>& cb) { m_packetArrivalCallback = cb; }

private:
	SOCKET m_socket{ INVALID_SOCK };
	HostEnt* m_host;
	SocketAddressIn m_dest, m_src;

	bool m_sniffing{ false }, m_stopped{ true };

	std::vector<SocketAddressIn> m_interfaces;
	std::vector<std::string> m_interfaceNames;

	std::function<void(Packet)> m_packetArrivalCallback{};

	std::mutex m_lock{};

//https://gist.github.com/austinmarton/2862515
	inline void createSocket() {
#ifdef _WIN32
		m_socket = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
#else
		m_socket = ::socket(AF_PACKET, SOCK_RAW, htons(0x0800));
#endif
		if (m_socket == INVALID_SOCK) {
			std::cout << __LINE__ <<  " - Socket inválido: " << errcode << std::endl;
			return;
		}
	}

	inline void sniffLoop() {
		std::vector<char> data;
		data.resize(0xFFFF);

		do {
			int count = recvfrom(m_socket, data.data(), data.size(), 0, nullptr, nullptr);
			if (count > 0) {
				auto buff = data.data();
				auto iphdr = reinterpret_cast<IPV4_HDR*>(buff);
				auto iphdrlen = iphdr->ip_header_len * 4;

				SocketAddressIn src, dest;
				memset(&src, 0, sizeof(src));
				memset(&dest, 0, sizeof(dest));

				src.sin_addr.s_addr = iphdr->ip_srcaddr;
				dest.sin_addr.s_addr = iphdr->ip_destaddr;

				Packet pak{};
				pak.from = std::string(inet_ntoa(src.sin_addr));
				pak.to = std::string(inet_ntoa(dest.sin_addr));

				switch (iphdr->ip_protocol) {
					case 6: { // Protocolo TCP
						auto tcp = reinterpret_cast<TCP_HDR*>(buff + iphdrlen);
						pak.type = "TCP";
						auto dataPtr = buff + iphdrlen + tcp->data_offset * 4;
						int dataSize = (count - tcp->data_offset * 4 - iphdrlen);
						pak.data = std::vector<char>(dataPtr, dataPtr + dataSize);
						pak.from += ":" + std::to_string(tcp->source_port);
						pak.to += ":" + std::to_string(tcp->dest_port);

						std::string dat(pak.data.begin(), pak.data.end());
						if (tcp->source_port == 80 ||
							tcp->source_port == 8080 ||
							tcp->source_port == 8008 ||
							tcp->source_port == 591 ||
							dat.find("HTTP/1.1") != dat.npos)
						{
							pak.type = "TCP*";
						}
					} break;
					case 17: { // Protocolo UDP
						auto udp = reinterpret_cast<UDP_HDR*>(buff + iphdrlen);
						pak.type = "UDP";
						auto dataPtr = buff + iphdrlen + sizeof(UDP_HDR);
						int dataSize = (count - sizeof(UDP_HDR) - iphdrlen);
						pak.data = std::vector<char>(dataPtr, dataPtr + dataSize);
						pak.from += ":" + std::to_string(udp->source_port);
						pak.to += ":" + std::to_string(udp->dest_port);

						std::string dat(pak.data.begin(), pak.data.end());
						if (udp->source_port == 8080 ||
							udp->source_port == 8008 ||
							udp->source_port == 591 ||
							dat.find("HTTP/1.1") != dat.npos)
						{
							pak.type = "UDP*";
						}
					} break;
					default: break;
				}

				if (!pak.type.empty()) {
					m_packetArrivalCallback(pak);
				}
			}
		} while (m_sniffing);
		m_stopped = true;

		int status = 0;
#ifdef _WIN32
		status = shutdown(m_socket, SD_BOTH);
		if (status == 0) { status = closesocket(m_socket); }
#else
		status = shutdown(m_socket, SHUT_RDWR);
		if (status == 0) { status = close(m_socket); }
#endif
		m_socket = -1;
	}

};

#endif // SNIFFER_HPP