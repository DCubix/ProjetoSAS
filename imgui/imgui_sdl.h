﻿#pragma once

struct ImDrawData;
struct SDL_Window;
struct SDL_Renderer;
union SDL_Event;

namespace ImGuiSDL
{
	// Call this to initialize the SDL renderer device that is internally used by the renderer.
	void Initialize(SDL_Renderer* renderer);
	// Call this before destroying your SDL renderer or ImGui to ensure that proper cleanup is done. This doesn't do anything critically important though,
	// so if you're fine with small memory leaks at the end of your application, you can even omit this.
	void Deinitialize();

	// Call this every frame after ImGui::Render with ImGui::GetDrawData(). This will use the SDL_Renderer provided to the interfrace with Initialize
	// to draw the contents of the draw data to the screen.
	void Render(SDL_Window* window, ImDrawData* drawData);

	bool ProcessEvent(SDL_Event* e);
};