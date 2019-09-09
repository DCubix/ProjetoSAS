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
#else
#error "Not supported"
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
		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
			std::cerr << __LINE__ <<  " - WSAStartup() falhou: " << WSAGetLastError() << std::endl;
			return;
		}
		m_interfaces.clear();
		m_interfaceNames.clear();

		m_socket = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
		if (m_socket == INVALID_SOCKET) {
			std::cout << __LINE__ <<  " - Socket inválido: " << WSAGetLastError() << std::endl;
			return;
		}

		char hostName[1024];
		if ((gethostname(hostName, 1024)) == SOCKET_ERROR) {
			std::cout << __LINE__ <<  " - Erro: " << WSAGetLastError() << std::endl;
			return;
		}

		if ((m_host = gethostbyname(hostName)) == NULL) {
			std::cout << __LINE__ <<  " - Erro: " << WSAGetLastError() << std::endl;
			return;
		}

		struct in_addr addr;
		for (int i = 0; m_host->h_addr_list[i] != 0; ++i) {
			memcpy(&addr, m_host->h_addr_list[i], sizeof(struct in_addr));
			std::cout << "\tN: " << i << " - End.: " << inet_ntoa(addr) << std::endl;
			m_interfaceNames.push_back(std::string(inet_ntoa(addr)));
		}
	}

	inline void start(int in) {
		// char hostName[1024];
		// if (gethostname(hostName, 1024) == SOCKET_ERROR) {
		// 	std::cout << "Erro ao recuperar o nome do Host: " << WSAGetLastError() << std::endl;
		// 	return;
		// }

		// if ((m_host = gethostbyname(hostName)) == nullptr) {
		// 	std::cout << "Erro ao recuperar o host pelo nome \"" << hostName << "\": " << WSAGetLastError() << std::endl;
		// 	return;
		// }

		// memset(&m_dest, 0, sizeof(SocketAddressIn));
		// m_dest.sin_family = AF_INET;
		// m_dest.sin_port = 0;
		// memcpy(&m_dest.sin_addr.s_addr, m_host->h_addr_list[0], sizeof(m_dest.sin_addr.s_addr));
		if (m_socket == INVALID_SOCKET) {
			m_socket = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
			if (m_socket == INVALID_SOCKET) {
				std::cout << __LINE__ <<  " - Socket inválido: " << WSAGetLastError() << std::endl;
				return;
			}
		}

		memset(&m_dest, 0, sizeof(SocketAddressIn));
		memcpy(&m_dest.sin_addr.s_addr, m_host->h_addr_list[in], sizeof(m_dest.sin_addr.s_addr));
		m_dest.sin_family = AF_INET;
		m_dest.sin_port = 0;

		if (::bind(m_socket, (SocketAddress*)&m_dest, sizeof(m_dest)) == SOCKET_ERROR) {
			std::cout << __LINE__ <<  " - Erro: " << WSAGetLastError() << std::endl;
			return;
		}

		// Modo promíscuo
		int j = 1;
		if (WSAIoctl(m_socket, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in, 0, 0) == SOCKET_ERROR) {
			std::cout << __LINE__ <<  " - Erro: " << WSAGetLastError() << std::endl;
			return;
		}

		m_sniffing = true;
		m_stopped = false;

		std::thread(Sniffer::sniffLoop, this).detach();
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
	SOCKET m_socket{ INVALID_SOCKET };
	HostEnt* m_host;
	SocketAddressIn m_dest, m_src;

	bool m_sniffing{ false }, m_stopped{ true };

	std::vector<SocketAddressIn> m_interfaces;
	std::vector<std::string> m_interfaceNames;

	std::function<void(Packet)> m_packetArrivalCallback{};

	std::mutex m_lock{};

	inline void sniffLoop() {
		std::vector<char> data;
		data.resize(0xFFFF);

		while (m_sniffing) {
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
		}
		m_stopped = true;
		closesocket(m_socket);
		m_socket = INVALID_SOCKET;
	}

};

#endif // SNIFFER_HPP