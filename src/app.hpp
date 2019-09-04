#ifndef APP_HPP
#define APP_HPP

#if __has_include("SDL2.h")
#include "SDL2.h"
#else
#include "SDL2/SDL.h"
#endif

#include "../imgui/imgui_sdl.h"
#include "../imgui/imgui.h"

#include <string>
#include <functional>

class Application {
public:
	inline Application(int width, int height, const std::string& title) {
		SDL_Init(SDL_INIT_EVERYTHING);

		m_window = SDL_CreateWindow(
			title.c_str(),
			SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
			width, height,
			SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE
		);

		m_renderer = SDL_CreateRenderer(m_window, -1, SDL_RENDERER_ACCELERATED);

		ImGui::CreateContext();
		ImGuiSDL::Initialize(m_renderer);
	}

	virtual ~Application() = default;

	inline int run(const std::function<void()>& gui) {
		bool run = true;
		while (run) {
			ImGuiIO& io = ImGui::GetIO();

			SDL_Event e;
			while (SDL_PollEvent(&e)) {
				if (e.type == SDL_QUIT) run = false;
				else if (e.type == SDL_WINDOWEVENT) {
					if (e.window.event == SDL_WINDOWEVENT_SIZE_CHANGED) {
						io.DisplaySize.x = static_cast<float>(e.window.data1);
						io.DisplaySize.y = static_cast<float>(e.window.data2);
					}
				}
				else ImGuiSDL::ProcessEvent(&e);
			}

			SDL_SetRenderDrawColor(m_renderer, 114, 144, 154, 255);
			SDL_RenderClear(m_renderer);

			ImGui::NewFrame();

			if (gui) gui();

			ImGui::Render();
			ImGuiSDL::Render(m_window, ImGui::GetDrawData());

			SDL_RenderPresent(m_renderer);
		}
		ImGuiSDL::Deinitialize();
		SDL_DestroyRenderer(m_renderer);
		SDL_DestroyWindow(m_window);

		ImGui::DestroyContext();
		return 0;
	}

private:
	SDL_Window* m_window;
	SDL_Renderer* m_renderer;
};

#endif // APP_HPP