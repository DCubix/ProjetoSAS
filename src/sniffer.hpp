#ifndef SNIFFER_HPP
#define SNIFFER_HPP

#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <functional>

#include <pcap.h>

#ifdef _WIN32
#include <stdio.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#endif

#include "headers.hpp"

struct Packet {
	std::string from, to, type;
	std::vector<char> data;
};

static void processPacket(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* buffer);

class Sniffer {
public:
	inline virtual ~Sniffer() = default;

	inline Sniffer() {
		pcap_if_t* alldevs;
		char err[128];
		if (pcap_findalldevs(&alldevs, err)) {
			std::cerr << "Erro PCAP (findalldevs): " << err << std::endl;
			return;
		}

		for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
			m_interfaces.push_back(std::string(dev->name));
			if (dev->description == nullptr) {
				m_interfaceNames.push_back(std::string(dev->name));
			} else {
				m_interfaceNames.push_back(std::string(dev->description));
			}
		}
	}

	inline void start(int in) {
		m_stopped = false;

		char err[128];
		m_handle = pcap_open_live(m_interfaces[in].c_str(), 65536, 1, 0, err);
		if (m_handle == nullptr) {
			std::cerr << "Erro PCAP (open_live): " << err << std::endl;
			return;
		}

		std::thread(&Sniffer::sniffLoop, this).detach();
	}

	inline void stop() {
		pcap_breakloop(m_handle);
		pcap_close(m_handle);
		m_handle = nullptr;
		m_stopped = true;
	}

	inline std::vector<std::string>& interfaceNames() { return m_interfaceNames; }
	inline std::vector<std::string>& interfaces() { return m_interfaces; }
	inline bool stopped() const { return m_stopped; }

	inline void onPacketArrival(const std::function<void(Packet)>& cb) { m_packetArrivalCallback = cb; }
	inline std::function<void(Packet)>& onPacketArrival() { return m_packetArrivalCallback; }

private:
	pcap_t* m_handle; // Dispositivo a ser farejado

	bool m_stopped{ true };

	std::vector<std::string> m_interfaces;
	std::vector<std::string> m_interfaceNames;

	std::function<void(Packet)> m_packetArrivalCallback{};

	inline void sniffLoop() {
		pcap_loop(m_handle, -1, processPacket, reinterpret_cast<unsigned char*>(this));
	}

};

inline void processPacket(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* buffer) {
	Sniffer* sniffer = reinterpret_cast<Sniffer*>(args);

	// Header ethernet
	auto ethhdr = reinterpret_cast<const ETH_HDR*>(buffer);

	// Header IP
	auto iphdr = reinterpret_cast<const IPV4_HDR*>(buffer + sizeof(ETH_HDR));
	auto iphdrlen = iphdr->ip_header_len * 4;
	auto offset = iphdrlen + sizeof(ETH_HDR);

	struct sockaddr_in src, dest;
	memset(&src, 0, sizeof(src));
	memset(&dest, 0, sizeof(dest));

	src.sin_addr.s_addr = iphdr->ip_srcaddr;
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	Packet pak{};
	pak.from = std::string(inet_ntoa(src.sin_addr));
	pak.to = std::string(inet_ntoa(dest.sin_addr));

	switch (iphdr->ip_protocol) {
		case 6: { // Protocolo TCP
			auto tcp = reinterpret_cast<const TCP_HDR*>(buffer + offset);
			int tcpHeaderSize = sizeof(ETH_HDR) + iphdrlen + tcp->data_offset * 4;

			auto dataPtr = buffer + tcpHeaderSize;
			int dataSize = (header->len - tcpHeaderSize);
			pak.data = std::vector<char>(dataPtr, dataPtr + dataSize);
			pak.from += ":" + std::to_string(ntohs(tcp->source_port));
			pak.to += ":" + std::to_string(ntohs(tcp->dest_port));

			std::string dat(pak.data.begin(), pak.data.end());
			if (tcp->source_port == 80 ||
				tcp->source_port == 8080 ||
				tcp->source_port == 8008 ||
				tcp->source_port == 591 ||
				dat.find("HTTP/1.1") != dat.npos)
			{
				pak.type = "TCP*";
			} else {
				pak.type = "TCP";
			}
		} break;
		case 17: { // Protocolo UDP
			auto udp = reinterpret_cast<const UDP_HDR*>(buffer + offset);
			int udpHeaderSize = sizeof(ETH_HDR) + iphdrlen + sizeof(UDP_HDR);

			auto dataPtr = buffer + udpHeaderSize;
			int dataSize = (header->len - udpHeaderSize);
			pak.data = std::vector<char>(dataPtr, dataPtr + dataSize);
			pak.from += ":" + std::to_string(ntohs(udp->source_port));
			pak.to += ":" + std::to_string(ntohs(udp->dest_port));

			std::string dat(pak.data.begin(), pak.data.end());
			if (udp->source_port == 8080 ||
				udp->source_port == 8008 ||
				udp->source_port == 591 ||
				dat.find("HTTP/1.1") != dat.npos)
			{
				pak.type = "UDP*";
			} else {
				pak.type = "UDP";
			}
		} break;
		default: break;
	}

	if (!pak.type.empty()) {
		sniffer->onPacketArrival()(pak);
	}
}

#endif // SNIFFER_HPP