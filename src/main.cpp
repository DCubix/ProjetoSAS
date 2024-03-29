#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <future>
#include <fstream>

#include "app.hpp"
#include "sniffer.hpp"
#include "OsDialog.hpp"
#include "../imgui/imgui_memory_editor.h"

#include "imgui_user.hpp"

struct PacketGUI {
	Packet p;
	bool selected;
};

static Sniffer m_sniffer{};
static std::vector<PacketGUI> g_Pacotes;
static std::vector<char> g_SelectedData;
static bool g_ScrollToBottom = false;

static MemoryEditor g_MemEdit{};

static ImGui::ColumnHeader headers[] = {
	{ "Origem", 170 },
	{ "Destino", 170 },
	{ "Tipo", 80 },
	{ "Dados", 200 },
	{ "", 32 }
};

static bool VectorOfStringGetter(void* data, int n, const char** out_text) {
	const std::vector<std::string>* v = (std::vector<std::string>*) data;
	*out_text = (*v)[n].c_str();
	return true;
}

void gui() {
	static bool data_view_open = false;
	static int selected_in = 0;

	bool anySelected = false;
	for (auto&& pak : g_Pacotes) {
		if (pak.selected) {
			anySelected = true;
			break;
		}
	}

	if (ImGui::Begin("Pacotes")) {
		ImGui::Combo(
			"Interfaces",
			&selected_in,
			VectorOfStringGetter,
			&m_sniffer.interfaceNames(),
			m_sniffer.interfaceNames().size()
		);
		ImGui::SameLine();
		if (m_sniffer.stopped()) {
			if (ImGui::Button("Iniciar")) {
				g_Pacotes.clear();
				m_sniffer.start(selected_in);
			}
		} else {
			if (ImGui::Button("Parar")) {
				m_sniffer.stop();
			}
		}
		ImGui::SameLine();
		if (ImGui::Button("Limpar")) {
			g_Pacotes.clear();
		}
		if (anySelected) {
			if (ImGui::Button("Concatenar e Salvar")) {
				std::vector<char> dados;
				dados.reserve(0xFFFF);
				for (auto&& pak : g_Pacotes) {
					if (!pak.selected) continue;
					dados.insert(dados.end(), pak.p.data.begin(), pak.p.data.end());
				}

				osd::Filters flt("Arquivo de Dados:dat");
				auto res = osd::Dialog::file(osd::DialogAction::SaveFile, ".", flt);
				if (res.has_value()) {
					std::ofstream of(res.value());
					if (of.good()) {
						of.write(dados.data(), dados.size());
						of.close();
					}
				}
			}
		}

		ImGui::ColumnHeaders("PacotesHeader", headers, IM_ARRAYSIZE(headers), true);
		ImGui::BeginColumnHeadersSync("PacotesContent", headers, IM_ARRAYSIZE(headers), true);
		int i = 0;
		for (auto&& pak : g_Pacotes) {
			auto&& p = pak.p;
			const char* id = (std::string("Ver##") + std::to_string(i)).c_str();
			const char* cid = (std::string("##") + std::to_string(i)).c_str();

			ImGui::Text(p.from.c_str());
			ImGui::NextColumn();
			ImGui::Text(p.to.c_str());
			ImGui::NextColumn();
			ImGui::Text(p.type.c_str());
			ImGui::NextColumn();

			if (!p.data.empty()) {
				if (ImGui::Button(id)) {
					data_view_open = true;
					g_SelectedData = p.data;
				}
				ImGui::SameLine();
			}
			ImGui::Text("(%d byte%s)", p.data.size(), p.data.size() == 0 || p.data.size() > 1 ? "s" : "");
			ImGui::NextColumn();

			ImGui::Checkbox(cid, &pak.selected);
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
}

int main(int argc, char** argv) {
	m_sniffer.onPacketArrival([&](Packet pak) {
		if (g_Pacotes.size() > 1024) {
			g_Pacotes.erase(g_Pacotes.begin());
		}
		PacketGUI pgui{};
		pgui.p = pak;
		pgui.selected = false;
		g_Pacotes.push_back(pgui);
		g_ScrollToBottom = true;
	});

	Application(640, 480, "Sniffer").run(gui);
	return 0;
}