#define NOMINMAX

#include <windows.h>
#include <intrin.h>
#include <stddef.h>
#include <stdint.h>
#include <cstdlib>
#include <iomanip>
#include <iostream>

// include cpueaxh
#include "cpueaxh.hpp"
#pragma comment(lib, "cpueaxh.lib")

// demo
#include "demo/escape/escape.hpp"
#include "demo/utils.hpp"
#include "demo/examples/guest.hpp"
#include "demo/examples/guest_hook/guest_hook_common.hpp"
#include "demo/examples/guest_hook/guest_hook_pre.hpp"
#include "demo/examples/guest_hook/guest_hook_post.hpp"
#include "demo/examples/guest_hook/guest_hook_exact.hpp"
#include "demo/examples/host.hpp"

static void present_demo(const char* title, const char* description, const char* success_hint) {
    std::system("cls");
    std::cout << "\n----------------------------------------\n";
    std::cout << title << "\n";
    std::cout << "Description: " << description << "\n";
    std::cout << "Success looks like: " << success_hint << "\n";
    std::cout << "Press any key to start this demo..." << std::endl;
    std::system("pause");
}

static void finish_demo() {
    std::cout << "\nPress any key to continue to the next demo..." << std::endl;
    std::system("pause");
}

int main() {
    // guest mode
    present_demo(
        "[1/6] guest basic demo",
        "Demonstrates basic guest-mode execution and register changes.",
        "The demo ends with CPUEAXH_ERR_OK and the after-state registers differ from the before-state as expected.");
    run_simple_function_demo();
    finish_demo();

    present_demo(
        "[2/6] guest hook pre demo",
        "Demonstrates a pre-execution hook that prints the current address and the next 16 bytes.",
        "You should see multiple lines starting with 'hook @', followed by CPUEAXH_ERR_OK.");
    run_guest_hook_pre_demo();
    finish_demo();

    present_demo(
        "[3/6] guest hook post demo",
        "Demonstrates a post-execution hook that prints RIP after the instruction finishes.",
        "You should see multiple lines starting with 'post @' showing RIP changes, followed by CPUEAXH_ERR_OK.");
    run_guest_hook_post_demo();
    finish_demo();

    present_demo(
        "[4/6] guest hook exact demo",
        "Demonstrates an exact-address hook that triggers only at one specific address.",
        "You should see exactly one 'exact hook hit @' line for the target address, followed by CPUEAXH_ERR_OK.");
    run_guest_hook_exact_demo();
    finish_demo();

    // host mode
    present_demo(
        "[5/6] host message box demo",
        "Demonstrates host-mode execution that calls the host-side MessageBox logic.",
        "A MessageBox should appear and the demo should complete without an error.");
    run_message_box_demo();
    finish_demo();

    present_demo(
        "[6/6] host memory patch demo",
        "Demonstrates host-mode memory patches that override reads and writes for specific host addresses during emulation.",
        "The MessageBox should show the patched text and caption, and the printed host-side strings should remain original after deleting the patches.");
    run_message_box_patch_demo();
    finish_demo();
    
    return 0;
}
