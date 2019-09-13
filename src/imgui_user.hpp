#ifndef IMGUI_USER_HPP
#define IMGUI_USER_HPP

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

#endif // IMGUI_USER_HPP