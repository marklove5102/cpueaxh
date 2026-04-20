#define NOMINMAX

#include <windows.h>
#include <intrin.h>
#include <stddef.h>
#include <stdint.h>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

// include cpueaxh
#include "cpueaxh.hpp"
#pragma comment(lib, "cpueaxh.lib")

// demo
#include "demo/escape/escape.hpp"
#include "demo/utils.hpp"
#include "demo/examples/guest.hpp"
#include "demo/examples/guest_hook/guest_hook_common.hpp"
#include "demo/examples/guest_hook/guest_hook_mem.hpp"
#include "demo/examples/guest_hook/guest_hook_mem_invalid.hpp"
#include "demo/examples/guest_hook/guest_hook_pre.hpp"
#include "demo/examples/guest_hook/guest_hook_post.hpp"
#include "demo/examples/guest_hook/guest_hook_exact.hpp"
#include "demo/examples/host.hpp"

// Interactive vs non-interactive presentation of a single demo. In non-
// interactive mode (selected via --demo N or --demo all on the command line)
// we skip the cls/pause so the output can be diffed and grepped without a
// human in the loop -- e.g. when verifying MEM_FETCH hook semantics in CI or
// from the agent.
static bool g_interactive = true;

static void present_demo(const char* title, const char* description, const char* success_hint) {
    if (g_interactive) {
        std::system("cls");
    }
    std::cout << "\n----------------------------------------\n";
    std::cout << title << "\n";
    std::cout << "Description: " << description << "\n";
    std::cout << "Success looks like: " << success_hint << "\n";
    if (g_interactive) {
        std::cout << "Press any key to start this demo..." << std::endl;
        std::system("pause");
    }
    else {
        std::cout << std::endl;
    }
}

static void finish_demo() {
    if (!g_interactive) {
        return;
    }
    std::cout << "\nPress any key to continue to the next demo..." << std::endl;
    std::system("pause");
}

struct DemoEntry {
    const char* title;
    const char* description;
    const char* success_hint;
    void (*run)();
};

static const DemoEntry kDemos[] = {
    {
        "[1/8] guest basic demo",
        "Demonstrates basic guest-mode execution and register changes.",
        "The demo ends with CPUEAXH_ERR_OK and the after-state registers differ from the before-state as expected.",
        run_simple_function_demo,
    },
    {
        "[2/8] guest hook pre demo",
        "Demonstrates a pre-execution hook that prints the current address and the next 16 bytes.",
        "You should see multiple lines starting with 'hook @', followed by CPUEAXH_ERR_OK.",
        run_guest_hook_pre_demo,
    },
    {
        "[3/8] guest hook post demo",
        "Demonstrates a post-execution hook that prints RIP after the instruction finishes.",
        "You should see multiple lines starting with 'post @' showing RIP changes, followed by CPUEAXH_ERR_OK.",
        run_guest_hook_post_demo,
    },
    {
        "[4/8] guest hook exact demo",
        "Demonstrates an exact-address hook that triggers only at one specific address.",
        "You should see exactly one 'exact hook hit @' line for the target address, followed by CPUEAXH_ERR_OK.",
        run_guest_hook_exact_demo,
    },
    {
        "[5/8] guest memory hook demo",
        "Demonstrates Unicorn-like memory access hooks for successful accesses plus a recoverable unmapped read callback.",
        "You should first see 'mem-fetch', 'mem-read', and 'mem-write', then a second run with 'mem-read-unmapped -> recovering' and a final CPUEAXH_ERR_OK.",
        run_guest_hook_mem_demo,
    },
    {
        "[6/8] guest invalid memory recovery demo",
        "Demonstrates Unicorn-style invalid memory hooks recovering both an unmapped read and a write-protection fault in one execution.",
        "You should see one 'mem-read-unmapped' hit, one 'mem-write-prot' hit, and a final 'invalid memory recovery test: PASS'.",
        run_guest_hook_mem_invalid_demo,
    },
    {
        "[7/8] host message box demo",
        "Demonstrates host-mode execution that calls the host-side MessageBox logic.",
        "A MessageBox should appear and the demo should complete without an error.",
        run_message_box_demo,
    },
    {
        "[8/8] host memory patch demo",
        "Demonstrates host-mode memory patches that override reads and writes for specific host addresses during emulation.",
        "The MessageBox should show the patched text and caption, and the printed host-side strings should remain original after deleting the patches.",
        run_message_box_patch_demo,
    },
};

constexpr int kDemoCount = (int)(sizeof(kDemos) / sizeof(kDemos[0]));

static void run_demo_at(int index) {
    const DemoEntry& demo = kDemos[index];
    present_demo(demo.title, demo.description, demo.success_hint);
    demo.run();
    finish_demo();
}

static void print_usage(const char* argv0) {
    std::cout << "usage: " << argv0 << " [--demo N|all]\n"
              << "  no args : interactive mode (cls + pause around every demo)\n"
              << "  --demo N: run only demo N (1.." << kDemoCount << "), no cls/pause\n"
              << "  --demo all: run every demo, no cls/pause\n"
              << std::endl;
}

int main(int argc, char** argv) {
    int single_demo = -1;
    bool run_all_noninteractive = false;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--demo") == 0 && i + 1 < argc) {
            const char* val = argv[i + 1];
            if (std::strcmp(val, "all") == 0) {
                run_all_noninteractive = true;
            }
            else {
                char* end = nullptr;
                long parsed = std::strtol(val, &end, 10);
                if (end == val || *end != '\0' || parsed < 1 || parsed > kDemoCount) {
                    std::cerr << "invalid demo index: " << val << std::endl;
                    print_usage(argv[0]);
                    return 1;
                }
                single_demo = (int)parsed - 1;
            }
            i++;
        }
        else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        else {
            std::cerr << "unknown arg: " << argv[i] << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    if (single_demo >= 0) {
        g_interactive = false;
        run_demo_at(single_demo);
        return 0;
    }
    if (run_all_noninteractive) {
        g_interactive = false;
        for (int i = 0; i < kDemoCount; i++) {
            run_demo_at(i);
        }
        return 0;
    }

    for (int i = 0; i < kDemoCount; i++) {
        run_demo_at(i);
    }
    return 0;
}
