#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <future>
#include <fstream>

#ifdef _WIN32
#include <stdio.h>
#include <winsock2.h>
#define SIO_RCVALL _WSAIOW(IOC_VENDOR, 1)
#else
#error "Not supported"
#endif

#include "app.hpp"
#include "headers.hpp"
#include "../osdialog/OsDialog.hpp"
#include "../imgui/imgui_memory_editor.h"

struct Packet {
	std::string from, to, type, desc;
	std::vector<char> data;
};

using AddrIn = struct sockaddr_in;

static SOCKET g_Sniffer;
static AddrIn g_Source;
static AddrIn g_Dest;

static std::vector<std::string> g_Addresses;
static std::vector<Packet> g_Pacotes;
static std::vector<char> g_SelectedData;
static bool g_Sniffing = false;
static bool g_ScrollToBottom = false;
static HOSTENT* g_Local = nullptr;
static std::mutex g_Lock;

static MemoryEditor g_MemEdit{};

namespace ImGui {
	struct ColumnHeader {
		const char* label      = NULL;
		float size       = -1.0f;
		float syncOffset = -1.0f;
	};

	void ColumnHeaders(const char* columnsId, ColumnHeader* headers, int count, bool border=true) {
		if(count<=0)
			return;

		ImGuiStyle & style = ImGui::GetStyle();
		const ImVec2 firstTextSize = ImGui::CalcTextSize(headers[0].label, NULL, true);

		ImGui::BeginChild(columnsId, ImVec2(0, firstTextSize.y + 2 * style.ItemSpacing.y + 2 * style.ItemInnerSpacing.y), true);

		const char* str_id = (std::string("col_") + std::string(columnsId)).c_str();

		ImGui::Columns(count, str_id, border);

		float offset = 0.0f;

		for(int i=0; i < count; i++)
		{
			ColumnHeader & header = headers[i];
			if(header.syncOffset < 0.0f)
			{
				ImGui::SetColumnOffset(i, offset);
				if(header.size >= 0)
				{
					offset += header.size;
				}
				else
				{
					const ImVec2 textsize = ImGui::CalcTextSize(header.label, NULL, true);
					offset += (textsize.x + 2 * style.ItemSpacing.x);
				}
			}
			else
			{
				ImGui::SetColumnOffset(i, header.syncOffset);
			}
			header.syncOffset = ImGui::GetColumnOffset(i);
			ImGui::Text(header.label);
			ImGui::NextColumn();
		}

		ImGui::Columns(1);
		ImGui::EndChild();
	}

	void BeginColumnHeadersSync(const char* columnsId, ColumnHeader* headers, int count, bool border=true)
	{
		if(count<=0)
			return;

		ImGui::BeginChild(columnsId, ImVec2(0,0), true);
		ImGui::Columns(count, columnsId, border);

		float offset = 0.0f;
		ImGuiStyle & style  = ImGui::GetStyle();

		for(int i=0; i < count; i++)
		{
			ColumnHeader & header = headers[i];
			ImGui::SetColumnOffset(i, header.syncOffset);
			header.syncOffset = ImGui::GetColumnOffset(i);
		}
	}

	void EndColumnHeadersSync(ColumnHeader* headers, int count)
	{
		if(count<=0)
			return;

		ImGui::Columns(1);
		ImGui::EndChild();
	}

}

// Baseado em https://gist.github.com/Accalmie/d328287c05f0a417892f
void listInterfaces() {
	if (g_Local != nullptr) return;

	char hostname[128];

	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
		std::cout << "Erro: " << WSAGetLastError() << std::endl;
		return;
	}

	std::cout << "Host: " << hostname << std::endl;

	g_Local = gethostbyname(hostname);
	std::cout << "Interfaces: " << std::endl;
	if (g_Local == nullptr) {
		std::cout << "Erro: " << WSAGetLastError() << std::endl;
		return;
	}

	g_Addresses.clear();

	struct in_addr addr;
	for (int i = 0; g_Local->h_addr_list[i] != 0; ++i) {
		memcpy(&addr, g_Local->h_addr_list[i], sizeof(struct in_addr));
		std::cout << "\tN: " << i << " - End.: " << inet_ntoa(addr) << std::endl;
		g_Addresses.push_back(std::string(inet_ntoa(addr)));
	}
}

void initializeSocket(int in) {
	g_Sniffing = true;
	g_Sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (g_Sniffer == INVALID_SOCKET) {
		std::cout << "Socket inválido." << std::endl;
		std::cout << "Erro: " << WSAGetLastError() << std::endl;
		return;
	}

	listInterfaces();

	if (g_Local == nullptr) {
		closesocket(g_Sniffer);
		return;
	}

	memset(&g_Dest, 0, sizeof(AddrIn));
	memcpy(&g_Dest.sin_addr.s_addr, g_Local->h_addr_list[in], sizeof(g_Dest.sin_addr.s_addr));
	g_Dest.sin_family = AF_INET;
	g_Dest.sin_port = 0;

	if (::bind(g_Sniffer, (struct sockaddr*)&g_Dest, sizeof(g_Dest)) == SOCKET_ERROR) {
		std::cout << "Falha no bind: " << g_Local->h_addr_list[in] << ": " << WSAGetLastError() << std::endl;
		return;
	}

	int j = 1;
	if (WSAIoctl(g_Sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR) {
		std::cout << "Erro: " << WSAGetLastError() << std::endl;
		return;
	}

	std::vector<char> data;
	data.resize(0xFFFF);

	while (g_Sniffing) {
		int count = recvfrom(g_Sniffer, data.data(), data.size(), 0, nullptr, nullptr);
		if (count > 0) {
			auto buff = data.data();
			auto iphdr = (IPV4_HDR*) buff;
			auto iphdrlen = iphdr->ip_header_len * 4;

			AddrIn src, dest;
			memset(&src, 0, sizeof(src));
			src.sin_addr.s_addr = iphdr->ip_srcaddr;

			memset(&dest, 0, sizeof(dest));
			dest.sin_addr.s_addr = iphdr->ip_destaddr;

			Packet pak{};
			pak.from = std::string(inet_ntoa(src.sin_addr));
			pak.to = std::string(inet_ntoa(dest.sin_addr));

			switch (iphdr->ip_protocol) {
				case 6: { // Protocolo TCP
					auto tcp = (TCP_HDR*)(buff + iphdrlen);
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
						pak.type = "TCP:http";
					}
				} break;
				case 17: { // Protocolo UDP
					auto udp = (UDP_HDR*)(buff + iphdrlen);
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
						pak.type = "UDP:http";
					}
				} break;
				case 1: { // Protocolo ICMP
					auto icmp = (ICMP_HDR*)(buff + iphdrlen);
					pak.type = "ICMP";
					pak.desc = "T: " + std::to_string(icmp->type) + " C: " + std::to_string(icmp->code);
					auto dataPtr = buff + iphdrlen + sizeof(ICMP_HDR);
					int dataSize = (count - sizeof(ICMP_HDR) - iphdrlen);
					pak.data = std::vector<char>(dataPtr, dataPtr + dataSize);
				} break;

				default: break;
			}

			if (!pak.type.empty()) {
				if (g_Pacotes.size() > 256) {
					g_Pacotes.erase(g_Pacotes.begin());
				}
				g_Pacotes.push_back(pak);
				g_ScrollToBottom = true;
			}

			//Sleep(500);
		}
	}

	closesocket(g_Sniffer);
}

static ImGui::ColumnHeader headers[] = {
	{ "Origem", 170 },
	{ "Destino", 170 },
	{ "Tipo", 80 },
	{ "Dados", 50 }
};

static bool VectorOfStringGetter(void* data, int n, const char** out_text) {
	const std::vector<std::string>* v = (std::vector<std::string>*) data;
	*out_text = (*v)[n].c_str();
	return true;
}

void gui() {
	g_Lock.lock();

	static bool data_view_open = false;
	static int selected_in = 0;

	if (ImGui::Begin("Pacotes")) {
		ImGui::Combo("Interfaces", &selected_in, VectorOfStringGetter, &g_Addresses, g_Addresses.size());
		ImGui::SameLine();
		if (!g_Sniffing) {
			if (ImGui::Button("Iniciar")) {
				g_Pacotes.clear();
				g_Sniffing = false;
				std::thread(initializeSocket, selected_in).detach();
			}
		} else {
			if (ImGui::Button("Parar")) {
				g_Sniffing = false;
			}
		}

		ImGui::ColumnHeaders("PacotesHeader", headers, IM_ARRAYSIZE(headers), true);
		ImGui::BeginColumnHeadersSync("PacotesContent", headers, IM_ARRAYSIZE(headers), true);
		int i = 0;
		for (auto&& p : g_Pacotes) {
			ImGui::Text(p.from.c_str());
			ImGui::NextColumn();
			ImGui::Text(p.to.c_str());
			ImGui::NextColumn();
			ImGui::Text(p.type.c_str());
			ImGui::NextColumn();
			// ImGui::Text(p.desc.c_str());
			// ImGui::NextColumn();
			if (p.data.empty()) {
				ImGui::Text("<VAZIO>");
			} else {
				const char* id = (std::string("Ver##") + std::to_string(i)).c_str();
				if (ImGui::Button(id)) {
					data_view_open = true;
					g_SelectedData = p.data;
				}
			}
			ImGui::NextColumn();
			i++;
		}
		if (g_ScrollToBottom) {
			ImGui::SetScrollHereY(1.0f);
			g_ScrollToBottom = false;
		}
		ImGui::EndColumnHeadersSync(headers, IM_ARRAYSIZE(headers));
	}
	ImGui::End();

	if (data_view_open) {
		ImGui::Begin("Dados", &data_view_open);
		if (ImGui::Button("Salvar")) {
			osd::Filters flt("Arquivo de Dados:dat");
			auto res = osd::Dialog::file(osd::DialogAction::SaveFile, ".", flt);
			if (res.has_value()) {
				std::ofstream of(res.value());
				if (of.good()) {
					of.write(g_SelectedData.data(), g_SelectedData.size());
					of.close();
				}
			}
		}
		g_MemEdit.DrawContents(g_SelectedData.data(), g_SelectedData.size());
		ImGui::End();
	}

	g_Lock.unlock();
}

int main(int argc, char** argv) {
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		std::cout << "WSAStartup() falhou." << std::endl;
		return 1;
	}

	listInterfaces();

	Application(640, 480, "Sniffer").run(gui);

	g_Sniffing = false;
	return 0;
}