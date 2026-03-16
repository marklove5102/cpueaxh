#pragma once

static const char* kexample_err_string(cpueaxh_err err) {
	switch (err) {
	case CPUEAXH_ERR_OK: return "CPUEAXH_ERR_OK";
	case CPUEAXH_ERR_NOMEM: return "CPUEAXH_ERR_NOMEM";
	case CPUEAXH_ERR_ARG: return "CPUEAXH_ERR_ARG";
	case CPUEAXH_ERR_ARCH: return "CPUEAXH_ERR_ARCH";
	case CPUEAXH_ERR_MODE: return "CPUEAXH_ERR_MODE";
	case CPUEAXH_ERR_MAP: return "CPUEAXH_ERR_MAP";
	case CPUEAXH_ERR_READ_UNMAPPED: return "CPUEAXH_ERR_READ_UNMAPPED";
	case CPUEAXH_ERR_WRITE_UNMAPPED: return "CPUEAXH_ERR_WRITE_UNMAPPED";
	case CPUEAXH_ERR_FETCH_UNMAPPED: return "CPUEAXH_ERR_FETCH_UNMAPPED";
	case CPUEAXH_ERR_EXCEPTION: return "CPUEAXH_ERR_EXCEPTION";
	case CPUEAXH_ERR_HOOK: return "CPUEAXH_ERR_HOOK";
	case CPUEAXH_ERR_READ_PROT: return "CPUEAXH_ERR_READ_PROT";
	case CPUEAXH_ERR_WRITE_PROT: return "CPUEAXH_ERR_WRITE_PROT";
	case CPUEAXH_ERR_FETCH_PROT: return "CPUEAXH_ERR_FETCH_PROT";
	case CPUEAXH_ERR_PATCH: return "CPUEAXH_ERR_PATCH";
	default: return "CPUEAXH_ERR_UNKNOWN";
	}
}

static void kexample_log(const char* text) {
	if (!text) {
		return;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "kexample: %s\n", text);
}
