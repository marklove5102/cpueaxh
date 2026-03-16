extern "C" {
#include <ntifs.h>
#include <wdf.h>
}

#include <intrin.h>

#include "cpueaxh.hpp"
#include "demo/utils.hpp"
#include "demo/escape/escape.hpp"
#include "demo/examples/host.hpp"

extern "C" DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD kexample_driver_unload;

VOID kexample_driver_unload(_In_ WDFDRIVER Driver) {
	UNREFERENCED_PARAMETER(Driver);
	kexample_log("driver unload");
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	WDF_DRIVER_CONFIG config;
	NTSTATUS status;

	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = kexample_driver_unload;

	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "kexample: WdfDriverCreate failed: 0x%08X\n", status);
		return status;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "kexample: running host-mode DbgPrintEx demo at IRQL=%lu\n", KeGetCurrentIrql());
	cpueaxh_err demo_err = run_host_dbgprint_demo_at_current_irql();
	if (demo_err != CPUEAXH_ERR_OK) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "kexample: host-mode DbgPrintEx demo finished with error: %s (%d)\n", kexample_err_string(demo_err), demo_err);
	}
	else {
		kexample_log("host-mode DbgPrintEx demo finished successfully");
	}

	return STATUS_SUCCESS;
}
