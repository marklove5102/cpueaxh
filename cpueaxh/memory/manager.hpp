// memory/manager.hpp - Virtual memory manager with page-granularity allocation

#pragma once

#include "../cpueaxh_platform.hpp"

#define CPUEAXH_PAGE_SIZE 0x1000ULL
#define CPUEAXH_PAGE_MASK (~(CPUEAXH_PAGE_SIZE - 1))
#define MM_PAGE_CACHE_SIZE 256u

#define MM_PROT_READ  0x1u
#define MM_PROT_WRITE 0x2u
#define MM_PROT_EXEC  0x4u

#define MM_CPU_ATTR_USER 0x1u

enum MM_ACCESS_STATUS : uint32_t {
    MM_ACCESS_OK = 0,
    MM_ACCESS_UNMAPPED = 1,
    MM_ACCESS_PROT = 2,
};

struct MEMORY_REGION {
    uint64_t base;
    uint64_t size;
    uint8_t* data;
    uint32_t perms;
    uint32_t cpu_attrs;
    bool external;
};

struct MM_PAGE_CACHE_ENTRY {
    uint64_t page_base;
    uint8_t* host_page;
    uint32_t perms;
    uint32_t cpu_attrs;
    bool external;
    bool host_passthrough;
    bool valid;
};

struct MM_DIRTY_SPAN {
    uint64_t base;
    uint64_t size;
    uint8_t* data;
    MM_DIRTY_SPAN* prev;
    MM_DIRTY_SPAN* next;
};

struct MM_DIRTY_CACHE_ENTRY {
    uint64_t page_base;
    MM_DIRTY_SPAN* span;
    bool valid;
};

struct MM_WRITE_ISOLATION_EXEMPT_RANGE {
    uint64_t base;
    uint64_t size;
    MM_WRITE_ISOLATION_EXEMPT_RANGE* next;
};

struct MM_WRITE_ISOLATION_GROUP {
    uint64_t handle;
    MM_DIRTY_SPAN* dirty_head;
    MM_DIRTY_SPAN* dirty_tail;
    MM_DIRTY_CACHE_ENTRY dirty_cache[MM_PAGE_CACHE_SIZE];
    MM_WRITE_ISOLATION_GROUP* next;
};

struct MM_PATCH_ENTRY {
    uint64_t handle;
    uint64_t address;
    uint64_t size;
    uint8_t* data;
};

enum MM_PATCH_STATUS : uint32_t {
    MM_PATCH_OK = 0,
    MM_PATCH_ARG = 1,
    MM_PATCH_NOMEM = 2,
    MM_PATCH_CONFLICT = 3,
    MM_PATCH_NOT_FOUND = 4,
};

struct MEMORY_MANAGER {
    MEMORY_REGION* regions;
    size_t region_count;
    size_t region_capacity;
    MM_PATCH_ENTRY* patches;
    size_t patch_count;
    size_t patch_capacity;
    uint64_t next_patch_handle;
    uint64_t next_write_isolation_group_handle;
    bool host_read_passthrough;
    bool host_write_passthrough;
    bool host_exec_passthrough;
    bool host_write_isolation_enabled;
    MM_WRITE_ISOLATION_GROUP* write_isolation_group_head;
    MM_WRITE_ISOLATION_GROUP* active_write_isolation_group;
    MM_DIRTY_SPAN* dirty_head;
    MM_DIRTY_SPAN* dirty_tail;
    MM_WRITE_ISOLATION_EXEMPT_RANGE* write_isolation_exempt_head;
    MM_PAGE_CACHE_ENTRY page_cache[MM_PAGE_CACHE_SIZE];
    MM_DIRTY_CACHE_ENTRY dirty_cache[MM_PAGE_CACHE_SIZE];
};

struct MM_ACCESS_INFO {
    uint8_t* ptr;
    uint32_t perms;
    uint32_t cpu_attrs;
    bool mapped;
    bool external;
    bool host_passthrough;
};

inline bool mm_patch_range_overlaps(uint64_t left_address, uint64_t left_size, uint64_t right_address, uint64_t right_size);
inline const MM_PATCH_ENTRY* mm_find_patch_const(const MEMORY_MANAGER* mgr, uint64_t address);
inline bool mm_query(MEMORY_MANAGER* mgr, uint64_t address, MM_ACCESS_INFO* out_info);
inline void mm_clear_write_isolation_groups(MEMORY_MANAGER* mgr);
inline bool mm_set_host_write_isolation(MEMORY_MANAGER* mgr, bool enabled);
inline bool mm_host_write_isolation_group_create(MEMORY_MANAGER* mgr, uint64_t* out_handle);
inline bool mm_host_write_isolation_group_select(MEMORY_MANAGER* mgr, uint64_t handle);
inline bool mm_host_write_isolation_group_delete(MEMORY_MANAGER* mgr, uint64_t handle);

inline uint64_t align_up_page(uint64_t size) {
    return (size + CPUEAXH_PAGE_SIZE - 1) & CPUEAXH_PAGE_MASK;
}

inline uint64_t align_down_page(uint64_t addr) {
    return addr & CPUEAXH_PAGE_MASK;
}

inline bool mm_is_page_aligned(uint64_t value) {
    return (value & (CPUEAXH_PAGE_SIZE - 1)) == 0;
}

inline bool mm_is_valid_perms(uint32_t perms) {
    return (perms & ~(MM_PROT_READ | MM_PROT_WRITE | MM_PROT_EXEC)) == 0;
}

inline bool mm_is_valid_cpu_attrs(uint32_t attrs) {
    return (attrs & ~MM_CPU_ATTR_USER) == 0;
}

inline bool mm_range_overflows(uint64_t address, uint64_t size) {
    return size != 0 && (address + size - 1) < address;
}

inline void mm_init(MEMORY_MANAGER* mgr) {
    CPUEAXH_MEMSET(mgr, 0, sizeof(MEMORY_MANAGER));
    mgr->next_patch_handle = 1;
    mgr->next_write_isolation_group_handle = 1;
}

inline void mm_invalidate_cache(MEMORY_MANAGER* mgr) {
    if (!mgr) {
        return;
    }
    CPUEAXH_MEMSET(mgr->page_cache, 0, sizeof(mgr->page_cache));
}

inline void mm_invalidate_dirty_cache(MEMORY_MANAGER* mgr) {
    if (!mgr) {
        return;
    }
    CPUEAXH_MEMSET(mgr->dirty_cache, 0, sizeof(mgr->dirty_cache));
}

inline uint32_t mm_host_passthrough_perms(const MEMORY_MANAGER* mgr) {
    uint32_t perms = 0;
    if (!mgr) {
        return 0;
    }
    if (mgr->host_read_passthrough) {
        perms |= MM_PROT_READ;
    }
    if (mgr->host_write_passthrough) {
        perms |= MM_PROT_WRITE;
    }
    if (mgr->host_exec_passthrough) {
        perms |= MM_PROT_EXEC;
    }
    return perms;
}

inline bool mm_has_host_passthrough(const MEMORY_MANAGER* mgr, uint32_t perm) {
    if (!mgr) {
        return false;
    }

    switch (perm) {
    case MM_PROT_READ:
        return mgr->host_read_passthrough;
    case MM_PROT_WRITE:
        return mgr->host_write_passthrough;
    case MM_PROT_EXEC:
        return mgr->host_exec_passthrough;
    default:
        return false;
    }
}

inline void mm_set_host_passthrough(MEMORY_MANAGER* mgr, uint32_t perms, bool enabled) {
    mgr->host_read_passthrough = enabled && ((perms & MM_PROT_READ) != 0);
    mgr->host_write_passthrough = enabled && ((perms & MM_PROT_WRITE) != 0);
    mgr->host_exec_passthrough = enabled && ((perms & MM_PROT_EXEC) != 0);
    mm_invalidate_cache(mgr);
}

inline void mm_release_dirty_span(MM_DIRTY_SPAN* span) {
    if (!span) {
        return;
    }
    if (span->data) {
        CPUEAXH_FREE(span->data);
    }
    CPUEAXH_FREE(span);
}

inline void mm_release_dirty_span_list(MM_DIRTY_SPAN* span) {
    while (span) {
        MM_DIRTY_SPAN* next = span->next;
        mm_release_dirty_span(span);
        span = next;
    }
}

inline void mm_sync_active_write_isolation_group(MEMORY_MANAGER* mgr) {
    if (!mgr || !mgr->active_write_isolation_group) {
        return;
    }
    mgr->active_write_isolation_group->dirty_head = mgr->dirty_head;
    mgr->active_write_isolation_group->dirty_tail = mgr->dirty_tail;
    CPUEAXH_MEMCPY(
        mgr->active_write_isolation_group->dirty_cache,
        mgr->dirty_cache,
        sizeof(mgr->dirty_cache));
}

inline void mm_load_write_isolation_group(MEMORY_MANAGER* mgr, MM_WRITE_ISOLATION_GROUP* group) {
    if (!mgr) {
        return;
    }
    mgr->active_write_isolation_group = group;
    if (!group) {
        mgr->dirty_head = NULL;
        mgr->dirty_tail = NULL;
        mm_invalidate_dirty_cache(mgr);
        return;
    }
    mgr->dirty_head = group->dirty_head;
    mgr->dirty_tail = group->dirty_tail;
    CPUEAXH_MEMCPY(mgr->dirty_cache, group->dirty_cache, sizeof(mgr->dirty_cache));
}

inline MM_WRITE_ISOLATION_GROUP* mm_find_write_isolation_group(MEMORY_MANAGER* mgr, uint64_t handle) {
    if (!mgr || handle == 0) {
        return NULL;
    }
    for (MM_WRITE_ISOLATION_GROUP* group = mgr->write_isolation_group_head; group; group = group->next) {
        if (group->handle == handle) {
            return group;
        }
    }
    return NULL;
}

inline bool mm_host_write_isolation_group_create(MEMORY_MANAGER* mgr, uint64_t* out_handle) {
    if (!mgr || !out_handle) {
        return false;
    }

    MM_WRITE_ISOLATION_GROUP* group = reinterpret_cast<MM_WRITE_ISOLATION_GROUP*>(CPUEAXH_ALLOC_ZEROED(sizeof(MM_WRITE_ISOLATION_GROUP)));
    if (!group) {
        return false;
    }

    group->handle = mgr->next_write_isolation_group_handle++;
    group->next = mgr->write_isolation_group_head;
    mgr->write_isolation_group_head = group;
    *out_handle = group->handle;
    return true;
}

inline bool mm_host_write_isolation_group_select(MEMORY_MANAGER* mgr, uint64_t handle) {
    if (!mgr || handle == 0) {
        return false;
    }

    MM_WRITE_ISOLATION_GROUP* group = mm_find_write_isolation_group(mgr, handle);
    if (!group) {
        return false;
    }

    mm_sync_active_write_isolation_group(mgr);
    mm_load_write_isolation_group(mgr, group);
    return true;
}

inline void mm_clear_dirty_spans(MEMORY_MANAGER* mgr) {
    if (!mgr) {
        return;
    }
    mm_release_dirty_span_list(mgr->dirty_head);
    mgr->dirty_head = NULL;
    mgr->dirty_tail = NULL;
    mm_invalidate_dirty_cache(mgr);
    if (mgr->active_write_isolation_group) {
        mgr->active_write_isolation_group->dirty_head = NULL;
        mgr->active_write_isolation_group->dirty_tail = NULL;
        CPUEAXH_MEMSET(
            mgr->active_write_isolation_group->dirty_cache,
            0,
            sizeof(mgr->active_write_isolation_group->dirty_cache));
    }
}

inline void mm_clear_write_isolation_exempt_ranges(MEMORY_MANAGER* mgr) {
    if (!mgr) {
        return;
    }
    MM_WRITE_ISOLATION_EXEMPT_RANGE* range = mgr->write_isolation_exempt_head;
    while (range) {
        MM_WRITE_ISOLATION_EXEMPT_RANGE* next = range->next;
        CPUEAXH_FREE(range);
        range = next;
    }
    mgr->write_isolation_exempt_head = NULL;
}

inline void mm_clear_write_isolation_groups(MEMORY_MANAGER* mgr) {
    if (!mgr) {
        return;
    }

    mm_sync_active_write_isolation_group(mgr);
    MM_WRITE_ISOLATION_GROUP* group = mgr->write_isolation_group_head;
    while (group) {
        MM_WRITE_ISOLATION_GROUP* next = group->next;
        mm_release_dirty_span_list(group->dirty_head);
        CPUEAXH_FREE(group);
        group = next;
    }
    mgr->write_isolation_group_head = NULL;
    mgr->active_write_isolation_group = NULL;
    mgr->dirty_head = NULL;
    mgr->dirty_tail = NULL;
    mm_invalidate_dirty_cache(mgr);
}

inline bool mm_set_host_write_isolation(MEMORY_MANAGER* mgr, bool enabled) {
    if (!mgr) {
        return false;
    }
    if (!enabled) {
        mm_clear_write_isolation_groups(mgr);
        mgr->host_write_isolation_enabled = false;
        return true;
    }
    if (!mgr->active_write_isolation_group) {
        uint64_t handle = 0;
        if (!mm_host_write_isolation_group_create(mgr, &handle)) {
            return false;
        }
        if (!mm_host_write_isolation_group_select(mgr, handle)) {
            return false;
        }
    }
    mgr->host_write_isolation_enabled = enabled;
    return true;
}

inline bool mm_host_write_isolation_group_delete(MEMORY_MANAGER* mgr, uint64_t handle) {
    if (!mgr || handle == 0) {
        return false;
    }

    mm_sync_active_write_isolation_group(mgr);

    MM_WRITE_ISOLATION_GROUP* previous = NULL;
    MM_WRITE_ISOLATION_GROUP* current = mgr->write_isolation_group_head;
    while (current && current->handle != handle) {
        previous = current;
        current = current->next;
    }
    if (!current) {
        return false;
    }

    MM_WRITE_ISOLATION_GROUP* replacement = NULL;
    if (current == mgr->active_write_isolation_group) {
        replacement = current->next ? current->next : mgr->write_isolation_group_head;
        if (replacement == current) {
            replacement = NULL;
        }
    }

    if (previous) {
        previous->next = current->next;
    }
    else {
        mgr->write_isolation_group_head = current->next;
    }

    if (current == mgr->active_write_isolation_group) {
        mm_load_write_isolation_group(mgr, replacement);
    }

    mm_release_dirty_span_list(current->dirty_head);
    CPUEAXH_FREE(current);

    if (mgr->host_write_isolation_enabled && !mgr->active_write_isolation_group) {
        uint64_t new_handle = 0;
        if (!mm_host_write_isolation_group_create(mgr, &new_handle)) {
            return false;
        }
        if (!mm_host_write_isolation_group_select(mgr, new_handle)) {
            return false;
        }
    }
    return true;
}

inline bool mm_host_write_isolation_exempt_contains(const MM_WRITE_ISOLATION_EXEMPT_RANGE* range, uint64_t address, uint64_t size) {
    if (!range || size == 0 || mm_range_overflows(address, size)) {
        return false;
    }
    const uint64_t end = address + size;
    return address >= range->base && end <= (range->base + range->size);
}

inline bool mm_is_host_write_isolation_exempt(const MEMORY_MANAGER* mgr, uint64_t address, uint64_t size) {
    if (!mgr || size == 0) {
        return false;
    }
    for (const MM_WRITE_ISOLATION_EXEMPT_RANGE* range = mgr->write_isolation_exempt_head; range; range = range->next) {
        if (mm_host_write_isolation_exempt_contains(range, address, size)) {
            return true;
        }
    }
    return false;
}

inline bool mm_add_host_write_isolation_exempt(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size) {
    if (!mgr || size == 0 || mm_range_overflows(address, size)) {
        return false;
    }
    for (MM_WRITE_ISOLATION_EXEMPT_RANGE* range = mgr->write_isolation_exempt_head; range; range = range->next) {
        if (range->base == address && range->size == size) {
            return true;
        }
    }

    MM_WRITE_ISOLATION_EXEMPT_RANGE* range = reinterpret_cast<MM_WRITE_ISOLATION_EXEMPT_RANGE*>(CPUEAXH_ALLOC_ZEROED(sizeof(MM_WRITE_ISOLATION_EXEMPT_RANGE)));
    if (!range) {
        return false;
    }

    range->base = address;
    range->size = size;
    range->next = mgr->write_isolation_exempt_head;
    mgr->write_isolation_exempt_head = range;
    return true;
}

inline bool mm_del_host_write_isolation_exempt(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size) {
    if (!mgr || size == 0) {
        return false;
    }

    MM_WRITE_ISOLATION_EXEMPT_RANGE* previous = NULL;
    MM_WRITE_ISOLATION_EXEMPT_RANGE* current = mgr->write_isolation_exempt_head;
    while (current) {
        if (current->base == address && current->size == size) {
            if (previous) {
                previous->next = current->next;
            }
            else {
                mgr->write_isolation_exempt_head = current->next;
            }
            CPUEAXH_FREE(current);
            return true;
        }
        previous = current;
        current = current->next;
    }

    return false;
}

inline size_t mm_dirty_cache_slot(uint64_t address) {
    return (size_t)((address >> 12) & (MM_PAGE_CACHE_SIZE - 1));
}

inline MM_DIRTY_SPAN* mm_find_dirty_span(MEMORY_MANAGER* mgr, uint64_t address) {
    if (!mgr) {
        return NULL;
    }

    const uint64_t page_base = align_down_page(address);
    MM_DIRTY_CACHE_ENTRY* cache_entry = &mgr->dirty_cache[mm_dirty_cache_slot(address)];
    if (cache_entry->valid && cache_entry->page_base == page_base && cache_entry->span) {
        MM_DIRTY_SPAN* cached = cache_entry->span;
        if (address >= cached->base && address < (cached->base + cached->size)) {
            return cached;
        }
    }

    for (MM_DIRTY_SPAN* span = mgr->dirty_head; span; span = span->next) {
        if (address < span->base) {
            break;
        }
        if (address < (span->base + span->size)) {
            cache_entry->valid = true;
            cache_entry->page_base = page_base;
            cache_entry->span = span;
            return span;
        }
    }

    return NULL;
}

inline bool mm_dirty_span_covers_range(MM_DIRTY_SPAN* span, uint64_t address, uint64_t size) {
    if (!span || size == 0 || mm_range_overflows(address, size)) {
        return false;
    }
    return address >= span->base && (address + size) <= (span->base + span->size);
}

inline bool mm_dirty_span_overlaps_range(MM_DIRTY_SPAN* span, uint64_t address, uint64_t size) {
    if (!span || size == 0 || mm_range_overflows(address, size)) {
        return false;
    }
    const uint64_t end = address + size;
    const uint64_t span_end = span->base + span->size;
    return !(span_end <= address || end <= span->base);
}

inline bool mm_has_dirty_overlap(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size) {
    if (!mgr || size == 0) {
        return false;
    }
    for (MM_DIRTY_SPAN* span = mgr->dirty_head; span; span = span->next) {
        if (span->base >= address + size) {
            break;
        }
        if (mm_dirty_span_overlaps_range(span, address, size)) {
            return true;
        }
    }
    return false;
}

inline bool mm_patch_has_overlap(const MEMORY_MANAGER* mgr, uint64_t address, uint64_t size) {
    if (!mgr || size == 0) {
        return false;
    }
    for (size_t index = 0; index < mgr->patch_count; ++index) {
        const MM_PATCH_ENTRY* patch = &mgr->patches[index];
        if (mm_patch_range_overlaps(address, size, patch->address, patch->size)) {
            return true;
        }
    }
    return false;
}

inline bool mm_read_visible_byte(MEMORY_MANAGER* mgr, uint64_t address, uint8_t* out_value) {
    if (!mgr || !out_value) {
        return false;
    }

    MM_DIRTY_SPAN* dirty_span = mm_find_dirty_span(mgr, address);
    if (dirty_span) {
        *out_value = dirty_span->data[address - dirty_span->base];
        return true;
    }

    if (mm_host_passthrough_perms(mgr) != 0) {
        const MM_PATCH_ENTRY* patch = mm_find_patch_const(mgr, address);
        if (patch) {
            *out_value = patch->data[address - patch->address];
            return true;
        }
    }

    MM_ACCESS_INFO info = {};
    if (!mm_query(mgr, address, &info) || !info.mapped || !info.ptr) {
        return false;
    }

    *out_value = *info.ptr;
    return true;
}

inline bool mm_copy_visible_range(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size, uint8_t* out_data) {
    if (!mgr || !out_data || size == 0 || mm_range_overflows(address, size)) {
        return false;
    }

    for (uint64_t offset = 0; offset < size; ++offset) {
        if (!mm_read_visible_byte(mgr, address + offset, &out_data[offset])) {
            return false;
        }
    }

    return true;
}

inline void mm_detach_dirty_span(MEMORY_MANAGER* mgr, MM_DIRTY_SPAN* span) {
    if (!mgr || !span) {
        return;
    }
    if (span->prev) {
        span->prev->next = span->next;
    }
    else {
        mgr->dirty_head = span->next;
    }
    if (span->next) {
        span->next->prev = span->prev;
    }
    else {
        mgr->dirty_tail = span->prev;
    }
    span->prev = NULL;
    span->next = NULL;
}

inline bool mm_insert_dirty_span_sorted(MEMORY_MANAGER* mgr, MM_DIRTY_SPAN* span) {
    if (!mgr || !span) {
        return false;
    }

    if (!mgr->dirty_head) {
        mgr->dirty_head = span;
        mgr->dirty_tail = span;
        mm_invalidate_dirty_cache(mgr);
        return true;
    }

    MM_DIRTY_SPAN* current = mgr->dirty_head;
    while (current && current->base < span->base) {
        current = current->next;
    }

    if (!current) {
        span->prev = mgr->dirty_tail;
        mgr->dirty_tail->next = span;
        mgr->dirty_tail = span;
    }
    else {
        span->next = current;
        span->prev = current->prev;
        if (current->prev) {
            current->prev->next = span;
        }
        else {
            mgr->dirty_head = span;
        }
        current->prev = span;
    }

    mm_invalidate_dirty_cache(mgr);
    return true;
}

inline bool mm_materialize_dirty_span(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size, MM_DIRTY_SPAN** out_span) {
    if (!mgr || !out_span || size == 0 || mm_range_overflows(address, size)) {
        return false;
    }

    uint64_t merged_base = align_down_page(address);
    uint64_t merged_end = align_up_page(address + size);
    for (MM_DIRTY_SPAN* span = mgr->dirty_head; span; span = span->next) {
        const uint64_t span_end = span->base + span->size;
        if (span_end < merged_base) {
            continue;
        }
        if (span->base > merged_end) {
            break;
        }
        if (span->base < merged_base) {
            merged_base = span->base;
        }
        if (span_end > merged_end) {
            merged_end = span_end;
        }
    }

    MM_DIRTY_SPAN* merged = reinterpret_cast<MM_DIRTY_SPAN*>(CPUEAXH_ALLOC_ZEROED(sizeof(MM_DIRTY_SPAN)));
    if (!merged) {
        return false;
    }

    merged->base = merged_base;
    merged->size = merged_end - merged_base;
    merged->data = reinterpret_cast<uint8_t*>(CPUEAXH_ALLOC_ZEROED((size_t)merged->size));
    if (!merged->data) {
        CPUEAXH_FREE(merged);
        return false;
    }

    if (!mm_copy_visible_range(mgr, merged->base, merged->size, merged->data)) {
        mm_release_dirty_span(merged);
        return false;
    }

    MM_DIRTY_SPAN* span = mgr->dirty_head;
    while (span) {
        MM_DIRTY_SPAN* next = span->next;
        if (mm_dirty_span_overlaps_range(span, merged->base, merged->size)) {
            mm_detach_dirty_span(mgr, span);
            mm_release_dirty_span(span);
        }
        span = next;
    }

    if (!mm_insert_dirty_span_sorted(mgr, merged)) {
        mm_release_dirty_span(merged);
        return false;
    }

    *out_span = merged;
    return true;
}

inline void mm_release_region(MEMORY_REGION* region) {
    if (!region) {
        return;
    }
    if (!region->external && region->data) {
        CPUEAXH_FREE(region->data);
    }
    CPUEAXH_MEMSET(region, 0, sizeof(*region));
}

inline bool mm_reserve_region_capacity(MEMORY_MANAGER* mgr, size_t capacity) {
    if (capacity <= mgr->region_capacity) {
        return true;
    }

    size_t new_capacity = mgr->region_capacity == 0 ? 16 : mgr->region_capacity;
    while (new_capacity < capacity) {
        if (new_capacity > ((size_t)-1) / 2) {
            new_capacity = capacity;
            break;
        }
        new_capacity *= 2;
    }

    MEMORY_REGION* new_regions = reinterpret_cast<MEMORY_REGION*>(
        CPUEAXH_ALLOC_ZEROED(new_capacity * sizeof(MEMORY_REGION)));
    if (!new_regions) {
        return false;
    }

    if (mgr->regions && mgr->region_count != 0) {
        CPUEAXH_MEMCPY(new_regions, mgr->regions, mgr->region_count * sizeof(MEMORY_REGION));
        CPUEAXH_FREE(mgr->regions);
    }

    mgr->regions = new_regions;
    mgr->region_capacity = new_capacity;
    return true;
}

inline bool mm_patch_range_overlaps(uint64_t left_address, uint64_t left_size, uint64_t right_address, uint64_t right_size) {
    if (left_size == 0 || right_size == 0) {
        return false;
    }

    const uint64_t left_end = left_address + left_size - 1;
    const uint64_t right_end = right_address + right_size - 1;
    return !(left_end < right_address || right_end < left_address);
}

inline bool mm_reserve_patch_capacity(MEMORY_MANAGER* mgr, size_t capacity) {
    if (capacity <= mgr->patch_capacity) {
        return true;
    }

    size_t new_capacity = mgr->patch_capacity == 0 ? 8 : mgr->patch_capacity;
    while (new_capacity < capacity) {
        if (new_capacity > ((size_t)-1) / 2) {
            new_capacity = capacity;
            break;
        }
        new_capacity *= 2;
    }

    MM_PATCH_ENTRY* new_patches = reinterpret_cast<MM_PATCH_ENTRY*>(
        CPUEAXH_ALLOC_ZEROED(new_capacity * sizeof(MM_PATCH_ENTRY)));
    if (!new_patches) {
        return false;
    }

    if (mgr->patches && mgr->patch_count != 0) {
        CPUEAXH_MEMCPY(new_patches, mgr->patches, mgr->patch_count * sizeof(MM_PATCH_ENTRY));
        CPUEAXH_FREE(mgr->patches);
    }

    mgr->patches = new_patches;
    mgr->patch_capacity = new_capacity;
    return true;
}

inline MM_PATCH_ENTRY* mm_find_patch(MEMORY_MANAGER* mgr, uint64_t address) {
    if (!mgr) {
        return NULL;
    }

    for (size_t index = 0; index < mgr->patch_count; ++index) {
        MM_PATCH_ENTRY* patch = &mgr->patches[index];
        if (patch->size == 0) {
            continue;
        }

        const uint64_t patch_end = patch->address + patch->size - 1;
        if (address >= patch->address && address <= patch_end) {
            return patch;
        }
    }

    return NULL;
}

inline const MM_PATCH_ENTRY* mm_find_patch_const(const MEMORY_MANAGER* mgr, uint64_t address) {
    return mm_find_patch(const_cast<MEMORY_MANAGER*>(mgr), address);
}

inline MM_PATCH_STATUS mm_add_patch(MEMORY_MANAGER* mgr, uint64_t* out_handle, uint64_t address, const void* bytes, uint64_t size) {
    if (!mgr || !out_handle || !bytes || size == 0 || mm_range_overflows(address, size)) {
        return MM_PATCH_ARG;
    }

    for (size_t index = 0; index < mgr->patch_count; ++index) {
        const MM_PATCH_ENTRY* patch = &mgr->patches[index];
        if (mm_patch_range_overlaps(address, size, patch->address, patch->size)) {
            return MM_PATCH_CONFLICT;
        }
    }

    if (!mm_reserve_patch_capacity(mgr, mgr->patch_count + 1)) {
        return MM_PATCH_NOMEM;
    }

    uint8_t* patch_bytes = reinterpret_cast<uint8_t*>(CPUEAXH_ALLOC_ZEROED((size_t)size));
    if (!patch_bytes) {
        return MM_PATCH_NOMEM;
    }

    CPUEAXH_MEMCPY(patch_bytes, bytes, (size_t)size);

    MM_PATCH_ENTRY* patch = &mgr->patches[mgr->patch_count++];
    patch->handle = mgr->next_patch_handle++;
    patch->address = address;
    patch->size = size;
    patch->data = patch_bytes;
    *out_handle = patch->handle;
    return MM_PATCH_OK;
}

inline MM_PATCH_STATUS mm_del_patch(MEMORY_MANAGER* mgr, uint64_t handle) {
    if (!mgr || handle == 0) {
        return MM_PATCH_ARG;
    }

    for (size_t index = 0; index < mgr->patch_count; ++index) {
        MM_PATCH_ENTRY* patch = &mgr->patches[index];
        if (patch->handle != handle) {
            continue;
        }

        if (patch->data) {
            CPUEAXH_FREE(patch->data);
        }

        if (index + 1 < mgr->patch_count) {
            CPUEAXH_MEMMOVE(
                &mgr->patches[index],
                &mgr->patches[index + 1],
                (mgr->patch_count - index - 1) * sizeof(MM_PATCH_ENTRY));
        }

        mgr->patch_count--;
        if (mgr->patch_count < mgr->patch_capacity) {
            CPUEAXH_MEMSET(&mgr->patches[mgr->patch_count], 0, sizeof(MM_PATCH_ENTRY));
        }
        return MM_PATCH_OK;
    }

    return MM_PATCH_NOT_FOUND;
}

inline size_t mm_find_insertion_index(const MEMORY_MANAGER* mgr, uint64_t base) {
    size_t left = 0;
    size_t right = mgr->region_count;
    while (left < right) {
        size_t mid = left + ((right - left) / 2);
        if (mgr->regions[mid].base < base) {
            left = mid + 1;
        }
        else {
            right = mid;
        }
    }
    return left;
}

inline size_t mm_find_region_index(const MEMORY_MANAGER* mgr, uint64_t address) {
    size_t left = 0;
    size_t right = mgr->region_count;

    while (left < right) {
        size_t mid = left + ((right - left) / 2);
        const MEMORY_REGION* region = &mgr->regions[mid];
        const uint64_t region_end = region->base + region->size;
        if (address < region->base) {
            right = mid;
        }
        else if (address >= region_end) {
            left = mid + 1;
        }
        else {
            return mid;
        }
    }

    return (size_t)-1;
}

inline MEMORY_REGION* mm_find_region(MEMORY_MANAGER* mgr, uint64_t address) {
    size_t index = mm_find_region_index(mgr, address);
    return index == (size_t)-1 ? NULL : &mgr->regions[index];
}

inline const MEMORY_REGION* mm_find_region_const(const MEMORY_MANAGER* mgr, uint64_t address) {
    size_t index = mm_find_region_index(mgr, address);
    return index == (size_t)-1 ? NULL : &mgr->regions[index];
}

inline bool mm_has_overlap(MEMORY_MANAGER* mgr, uint64_t base, uint64_t size) {
    if (size == 0 || mm_range_overflows(base, size)) {
        return true;
    }

    const uint64_t end = base + size;
    size_t index = mm_find_insertion_index(mgr, base);

    if (index > 0) {
        const MEMORY_REGION* previous = &mgr->regions[index - 1];
        if ((previous->base + previous->size) > base) {
            return true;
        }
    }

    if (index < mgr->region_count) {
        const MEMORY_REGION* current = &mgr->regions[index];
        if (current->base < end) {
            return true;
        }
    }

    return false;
}

inline bool mm_insert_region(MEMORY_MANAGER* mgr, size_t index, const MEMORY_REGION* region) {
    if (!mm_reserve_region_capacity(mgr, mgr->region_count + 1)) {
        return false;
    }

    if (index < mgr->region_count) {
        CPUEAXH_MEMMOVE(
            &mgr->regions[index + 1],
            &mgr->regions[index],
            (mgr->region_count - index) * sizeof(MEMORY_REGION));
    }

    mgr->regions[index] = *region;
    mgr->region_count++;
    return true;
}

inline bool mm_replace_region(MEMORY_MANAGER* mgr, size_t index, const MEMORY_REGION* replacements, size_t replacement_count) {
    if (index >= mgr->region_count) {
        return false;
    }

    const size_t new_count = mgr->region_count - 1 + replacement_count;
    if (!mm_reserve_region_capacity(mgr, new_count)) {
        return false;
    }

    MEMORY_REGION original = mgr->regions[index];
    const size_t tail_count = mgr->region_count - index - 1;

    if (replacement_count > 1) {
        CPUEAXH_MEMMOVE(
            &mgr->regions[index + replacement_count],
            &mgr->regions[index + 1],
            tail_count * sizeof(MEMORY_REGION));
    }
    else if (replacement_count == 0 && tail_count != 0) {
        CPUEAXH_MEMMOVE(
            &mgr->regions[index],
            &mgr->regions[index + 1],
            tail_count * sizeof(MEMORY_REGION));
    }

    for (size_t i = 0; i < replacement_count; i++) {
        mgr->regions[index + i] = replacements[i];
    }

    mgr->region_count = new_count;
    mm_release_region(&original);
    mm_invalidate_cache(mgr);
    return true;
}

inline bool mm_check_range_mapped(const MEMORY_MANAGER* mgr, uint64_t address, uint64_t size) {
    if (size == 0) {
        return true;
    }
    if (mm_range_overflows(address, size)) {
        return false;
    }

    const uint64_t end = address + size;
    uint64_t current = address;

    while (current < end) {
        size_t index = mm_find_region_index(mgr, current);
        if (index == (size_t)-1) {
            return false;
        }

        const MEMORY_REGION* region = &mgr->regions[index];
        const uint64_t region_end = region->base + region->size;
        if (region_end <= current) {
            return false;
        }

        current = region_end < end ? region_end : end;
    }

    return true;
}

inline bool mm_build_region_segment(
    const MEMORY_REGION* source,
    uint64_t segment_base,
    uint64_t segment_size,
    uint32_t perms,
    uint32_t cpu_attrs,
    MEMORY_REGION* out_region) {
    if (!source || !out_region || segment_size == 0) {
        return false;
    }

    CPUEAXH_MEMSET(out_region, 0, sizeof(*out_region));
    out_region->base = segment_base;
    out_region->size = segment_size;
    out_region->perms = perms;
    out_region->cpu_attrs = cpu_attrs;
    out_region->external = source->external;

    const uint64_t offset = segment_base - source->base;
    if (source->external) {
        out_region->data = source->data + offset;
        return true;
    }

    out_region->data = reinterpret_cast<uint8_t*>(CPUEAXH_ALLOC_ZEROED((size_t)segment_size));
    if (!out_region->data) {
        return false;
    }

    CPUEAXH_MEMCPY(out_region->data, source->data + offset, (size_t)segment_size);
    return true;
}

inline bool mm_map_internal(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size, uint32_t perms) {
    if (size == 0 || !mm_is_page_aligned(address) || !mm_is_page_aligned(size) || mm_range_overflows(address, size)) {
        return false;
    }
    if (!mm_is_valid_perms(perms) || mm_has_overlap(mgr, address, size)) {
        return false;
    }

    MEMORY_REGION region = {};
    region.base = address;
    region.size = size;
    region.perms = perms;
    region.cpu_attrs = MM_CPU_ATTR_USER;
    region.external = false;
    region.data = reinterpret_cast<uint8_t*>(CPUEAXH_ALLOC_ZEROED((size_t)size));
    if (!region.data) {
        return false;
    }

    bool inserted = mm_insert_region(mgr, mm_find_insertion_index(mgr, address), &region);
    if (!inserted) {
        mm_release_region(&region);
        return false;
    }

    mm_invalidate_cache(mgr);
    return true;
}

inline bool mm_map_host(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size, uint32_t perms, void* host_ptr) {
    if (size == 0 || host_ptr == NULL || !mm_is_page_aligned(address) || !mm_is_page_aligned(size) || mm_range_overflows(address, size)) {
        return false;
    }
    if (!mm_is_valid_perms(perms) || mm_has_overlap(mgr, address, size)) {
        return false;
    }

    MEMORY_REGION region = {};
    region.base = address;
    region.size = size;
    region.data = reinterpret_cast<uint8_t*>(host_ptr);
    region.perms = perms;
    region.cpu_attrs = MM_CPU_ATTR_USER;
    region.external = true;

    bool inserted = mm_insert_region(mgr, mm_find_insertion_index(mgr, address), &region);
    if (!inserted) {
        return false;
    }

    mm_invalidate_cache(mgr);
    return true;
}

inline bool mm_alloc(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size) {
    return mm_map_internal(mgr, address, size, MM_PROT_READ | MM_PROT_WRITE | MM_PROT_EXEC);
}

inline bool mm_unmap(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size) {
    if (size == 0) {
        return true;
    }
    if (!mm_is_page_aligned(address) || !mm_is_page_aligned(size) || mm_range_overflows(address, size)) {
        return false;
    }
    if (!mm_check_range_mapped(mgr, address, size)) {
        return false;
    }

    const uint64_t end = address + size;
    uint64_t current = address;

    while (current < end) {
        size_t index = mm_find_region_index(mgr, current);
        if (index == (size_t)-1) {
            return false;
        }

        const MEMORY_REGION original = mgr->regions[index];
        const uint64_t original_end = original.base + original.size;
        const uint64_t chunk_end = original_end < end ? original_end : end;

        MEMORY_REGION replacements[2] = {};
        size_t replacement_count = 0;

        if (original.base < current) {
            if (!mm_build_region_segment(&original, original.base, current - original.base, original.perms, original.cpu_attrs, &replacements[replacement_count++])) {
                for (size_t i = 0; i < replacement_count; i++) {
                    mm_release_region(&replacements[i]);
                }
                return false;
            }
        }

        if (chunk_end < original_end) {
            if (!mm_build_region_segment(&original, chunk_end, original_end - chunk_end, original.perms, original.cpu_attrs, &replacements[replacement_count++])) {
                for (size_t i = 0; i < replacement_count; i++) {
                    mm_release_region(&replacements[i]);
                }
                return false;
            }
        }

        if (!mm_replace_region(mgr, index, replacements, replacement_count)) {
            for (size_t i = 0; i < replacement_count; i++) {
                mm_release_region(&replacements[i]);
            }
            return false;
        }

        current = chunk_end;
    }

    return true;
}

inline bool mm_protect(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size, uint32_t perms) {
    if (size == 0) {
        return true;
    }
    if (!mm_is_page_aligned(address) || !mm_is_page_aligned(size) || mm_range_overflows(address, size)) {
        return false;
    }
    if (!mm_is_valid_perms(perms) || !mm_check_range_mapped(mgr, address, size)) {
        return false;
    }

    const uint64_t end = address + size;
    uint64_t current = address;

    while (current < end) {
        size_t index = mm_find_region_index(mgr, current);
        if (index == (size_t)-1) {
            return false;
        }

        const MEMORY_REGION original = mgr->regions[index];
        const uint64_t original_end = original.base + original.size;
        const uint64_t chunk_end = original_end < end ? original_end : end;

        MEMORY_REGION replacements[3] = {};
        size_t replacement_count = 0;

        if (original.base < current) {
            if (!mm_build_region_segment(&original, original.base, current - original.base, original.perms, original.cpu_attrs, &replacements[replacement_count++])) {
                for (size_t i = 0; i < replacement_count; i++) {
                    mm_release_region(&replacements[i]);
                }
                return false;
            }
        }

        if (!mm_build_region_segment(&original, current, chunk_end - current, perms, original.cpu_attrs, &replacements[replacement_count++])) {
            for (size_t i = 0; i < replacement_count; i++) {
                mm_release_region(&replacements[i]);
            }
            return false;
        }

        if (chunk_end < original_end) {
            if (!mm_build_region_segment(&original, chunk_end, original_end - chunk_end, original.perms, original.cpu_attrs, &replacements[replacement_count++])) {
                for (size_t i = 0; i < replacement_count; i++) {
                    mm_release_region(&replacements[i]);
                }
                return false;
            }
        }

        if (!mm_replace_region(mgr, index, replacements, replacement_count)) {
            for (size_t i = 0; i < replacement_count; i++) {
                mm_release_region(&replacements[i]);
            }
            return false;
        }

        current = chunk_end;
    }

    return true;
}

inline bool mm_set_cpu_attrs(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size, uint32_t cpu_attrs) {
    if (size == 0) {
        return true;
    }
    if (!mm_is_page_aligned(address) || !mm_is_page_aligned(size) || mm_range_overflows(address, size)) {
        return false;
    }
    if (!mm_is_valid_cpu_attrs(cpu_attrs) || !mm_check_range_mapped(mgr, address, size)) {
        return false;
    }

    const uint64_t end = address + size;
    uint64_t current = address;

    while (current < end) {
        size_t index = mm_find_region_index(mgr, current);
        if (index == (size_t)-1) {
            return false;
        }

        const MEMORY_REGION original = mgr->regions[index];
        const uint64_t original_end = original.base + original.size;
        const uint64_t chunk_end = original_end < end ? original_end : end;

        MEMORY_REGION replacements[3] = {};
        size_t replacement_count = 0;

        if (original.base < current) {
            if (!mm_build_region_segment(&original, original.base, current - original.base, original.perms, original.cpu_attrs, &replacements[replacement_count++])) {
                for (size_t i = 0; i < replacement_count; i++) {
                    mm_release_region(&replacements[i]);
                }
                return false;
            }
        }

        if (!mm_build_region_segment(&original, current, chunk_end - current, original.perms, cpu_attrs, &replacements[replacement_count++])) {
            for (size_t i = 0; i < replacement_count; i++) {
                mm_release_region(&replacements[i]);
            }
            return false;
        }

        if (chunk_end < original_end) {
            if (!mm_build_region_segment(&original, chunk_end, original_end - chunk_end, original.perms, original.cpu_attrs, &replacements[replacement_count++])) {
                for (size_t i = 0; i < replacement_count; i++) {
                    mm_release_region(&replacements[i]);
                }
                return false;
            }
        }

        if (!mm_replace_region(mgr, index, replacements, replacement_count)) {
            for (size_t i = 0; i < replacement_count; i++) {
                mm_release_region(&replacements[i]);
            }
            return false;
        }

        current = chunk_end;
    }

    return true;
}

inline size_t mm_cache_slot(uint64_t address) {
    return (size_t)((address >> 12) & (MM_PAGE_CACHE_SIZE - 1));
}

inline bool mm_query(MEMORY_MANAGER* mgr, uint64_t address, MM_ACCESS_INFO* out_info) {
    if (!mgr || !out_info) {
        return false;
    }

    const uint64_t page_base = align_down_page(address);
    const size_t slot = mm_cache_slot(address);
    MM_PAGE_CACHE_ENTRY* cache_entry = &mgr->page_cache[slot];
    if (cache_entry->valid && cache_entry->page_base == page_base) {
        out_info->ptr = cache_entry->host_page + (size_t)(address - page_base);
        out_info->perms = cache_entry->perms;
        out_info->cpu_attrs = cache_entry->cpu_attrs;
        out_info->mapped = true;
        out_info->external = cache_entry->external;
        out_info->host_passthrough = cache_entry->host_passthrough;
        return true;
    }

    size_t index = mm_find_region_index(mgr, address);
    if (index != (size_t)-1) {
        MEMORY_REGION* region = &mgr->regions[index];
        cache_entry->valid = true;
        cache_entry->page_base = page_base;
        cache_entry->host_page = region->data + (page_base - region->base);
        cache_entry->perms = region->perms;
        cache_entry->cpu_attrs = region->cpu_attrs;
        cache_entry->external = region->external;
        cache_entry->host_passthrough = false;

        out_info->ptr = cache_entry->host_page + (size_t)(address - page_base);
        out_info->perms = cache_entry->perms;
        out_info->cpu_attrs = cache_entry->cpu_attrs;
        out_info->mapped = true;
        out_info->external = cache_entry->external;
        out_info->host_passthrough = cache_entry->host_passthrough;
        return true;
    }

    const uint32_t host_perms = mm_host_passthrough_perms(mgr);
    if (host_perms != 0) {
        cache_entry->valid = true;
        cache_entry->page_base = page_base;
        cache_entry->host_page = reinterpret_cast<uint8_t*>((uintptr_t)page_base);
        cache_entry->perms = host_perms;
        cache_entry->cpu_attrs = MM_CPU_ATTR_USER;
        cache_entry->external = false;
        cache_entry->host_passthrough = true;

        out_info->ptr = cache_entry->host_page + (size_t)(address - page_base);
        out_info->perms = cache_entry->perms;
        out_info->cpu_attrs = cache_entry->cpu_attrs;
        out_info->mapped = true;
        out_info->external = cache_entry->external;
        out_info->host_passthrough = cache_entry->host_passthrough;
        return true;
    }

    out_info->ptr = NULL;
    out_info->perms = 0;
    out_info->cpu_attrs = 0;
    out_info->mapped = false;
    out_info->external = false;
    out_info->host_passthrough = false;
    return true;
}

inline MM_ACCESS_STATUS mm_get_ptr_checked_ex(MEMORY_MANAGER* mgr, uint64_t address, uint32_t perm, uint8_t** out_ptr, uint32_t* out_cpu_attrs, bool apply_write_isolation) {
    if (!out_ptr) {
        return MM_ACCESS_UNMAPPED;
    }

    MM_ACCESS_INFO info = {};
    if (!mm_query(mgr, address, &info) || !info.mapped) {
        *out_ptr = NULL;
        if (out_cpu_attrs) {
            *out_cpu_attrs = 0;
        }
        return MM_ACCESS_UNMAPPED;
    }

    if ((info.perms & perm) == 0) {
        *out_ptr = NULL;
        if (out_cpu_attrs) {
            *out_cpu_attrs = info.cpu_attrs;
        }
        return MM_ACCESS_PROT;
    }

    if (mgr->host_write_isolation_enabled && perm != MM_PROT_EXEC) {
        MM_DIRTY_SPAN* dirty_span = mm_find_dirty_span(mgr, address);
        if (dirty_span) {
            *out_ptr = dirty_span->data + (size_t)(address - dirty_span->base);
            if (out_cpu_attrs) {
                *out_cpu_attrs = info.cpu_attrs;
            }
            return MM_ACCESS_OK;
        }

        if (perm == MM_PROT_WRITE && apply_write_isolation && (info.external || info.host_passthrough) &&
            !mm_is_host_write_isolation_exempt(mgr, address, 1)) {
            if (!info.ptr) {
                *out_ptr = NULL;
                return MM_ACCESS_UNMAPPED;
            }

            MM_DIRTY_SPAN* materialized = NULL;
            if (!mm_materialize_dirty_span(mgr, address, 1, &materialized)) {
                *out_ptr = NULL;
                return MM_ACCESS_UNMAPPED;
            }
            *out_ptr = materialized->data + (size_t)(address - materialized->base);
            if (out_cpu_attrs) {
                *out_cpu_attrs = info.cpu_attrs;
            }
            return MM_ACCESS_OK;
        }
    }

    const MM_PATCH_ENTRY* patch = NULL;
    if (mm_host_passthrough_perms(mgr) != 0) {
        patch = mm_find_patch_const(mgr, address);
    }

    if (patch) {
        *out_ptr = patch->data + (size_t)(address - patch->address);
    }
    else {
        *out_ptr = info.ptr;
    }

    if (out_cpu_attrs) {
        *out_cpu_attrs = info.cpu_attrs;
    }
    return MM_ACCESS_OK;
}

inline MM_ACCESS_STATUS mm_get_ptr_checked(MEMORY_MANAGER* mgr, uint64_t address, uint32_t perm, uint8_t** out_ptr, uint32_t* out_cpu_attrs = NULL) {
    return mm_get_ptr_checked_ex(mgr, address, perm, out_ptr, out_cpu_attrs, false);
}

inline MM_ACCESS_STATUS mm_get_contiguous_ptr_checked(MEMORY_MANAGER* mgr, uint64_t address, uint64_t size, uint32_t perm, uint8_t** out_ptr, uint32_t* out_cpu_attrs = NULL, bool apply_write_isolation = false) {
    if (!out_ptr || size == 0 || mm_range_overflows(address, size)) {
        if (out_ptr) {
            *out_ptr = NULL;
        }
        return MM_ACCESS_UNMAPPED;
    }

    uint8_t* first_ptr = NULL;
    uint32_t first_cpu_attrs = 0;
    MM_ACCESS_INFO first_info = {};
    if (!mm_query(mgr, address, &first_info) || !first_info.mapped) {
        *out_ptr = NULL;
        if (out_cpu_attrs) {
            *out_cpu_attrs = 0;
        }
        return MM_ACCESS_UNMAPPED;
    }
    if ((first_info.perms & perm) == 0) {
        *out_ptr = NULL;
        if (out_cpu_attrs) {
            *out_cpu_attrs = first_info.cpu_attrs;
        }
        return MM_ACCESS_PROT;
    }

    if (perm == MM_PROT_WRITE && !mgr->host_write_isolation_enabled) {
        MM_ACCESS_STATUS status = mm_get_ptr_checked_ex(mgr, address, perm, &first_ptr, &first_cpu_attrs, false);
        if (status != MM_ACCESS_OK) {
            *out_ptr = NULL;
            if (out_cpu_attrs) {
                *out_cpu_attrs = first_cpu_attrs;
            }
            return status;
        }

        for (uint64_t offset = 1; offset < size; ++offset) {
            uint8_t* next_ptr = NULL;
            uint32_t next_cpu_attrs = 0;
            status = mm_get_ptr_checked_ex(mgr, address + offset, perm, &next_ptr, &next_cpu_attrs, false);
            if (status != MM_ACCESS_OK) {
                *out_ptr = NULL;
                if (out_cpu_attrs) {
                    *out_cpu_attrs = next_cpu_attrs;
                }
                return status;
            }
            if (next_ptr != first_ptr + offset) {
                *out_ptr = NULL;
                if (out_cpu_attrs) {
                    *out_cpu_attrs = next_cpu_attrs;
                }
                return MM_ACCESS_PROT;
            }
        }

        *out_ptr = first_ptr;
        if (out_cpu_attrs) {
            *out_cpu_attrs = first_cpu_attrs;
        }
        return MM_ACCESS_OK;
    }

    bool needs_materialized_span = false;
    bool all_isolatable = true;
    for (uint64_t offset = 0; offset < size; ++offset) {
        MM_ACCESS_INFO info = {};
        if (!mm_query(mgr, address + offset, &info) || !info.mapped) {
            *out_ptr = NULL;
            if (out_cpu_attrs) {
                *out_cpu_attrs = 0;
            }
            return MM_ACCESS_UNMAPPED;
        }
        if ((info.perms & perm) == 0) {
            *out_ptr = NULL;
            if (out_cpu_attrs) {
                *out_cpu_attrs = info.cpu_attrs;
            }
            return MM_ACCESS_PROT;
        }

        MM_DIRTY_SPAN* dirty_span = mm_find_dirty_span(mgr, address + offset);
        if (dirty_span || (mm_host_passthrough_perms(mgr) != 0 && mm_find_patch_const(mgr, address + offset) != NULL)) {
            needs_materialized_span = true;
        }

        if (apply_write_isolation && perm == MM_PROT_WRITE && (info.external || info.host_passthrough) &&
            !mm_is_host_write_isolation_exempt(mgr, address + offset, 1)) {
            needs_materialized_span = true;
        }
        else if (apply_write_isolation && perm == MM_PROT_WRITE && (info.external || info.host_passthrough)) {
            all_isolatable = false;
        }
    }

    if (apply_write_isolation && perm == MM_PROT_WRITE && needs_materialized_span && !all_isolatable) {
        needs_materialized_span = false;
    }

    if (!needs_materialized_span) {
        MM_ACCESS_STATUS status = mm_get_ptr_checked_ex(mgr, address, perm, &first_ptr, &first_cpu_attrs, false);
        if (status != MM_ACCESS_OK) {
            *out_ptr = NULL;
            if (out_cpu_attrs) {
                *out_cpu_attrs = first_cpu_attrs;
            }
            return status;
        }

        for (uint64_t offset = 1; offset < size; ++offset) {
            uint8_t* next_ptr = NULL;
            uint32_t next_cpu_attrs = 0;
            status = mm_get_ptr_checked_ex(mgr, address + offset, perm, &next_ptr, &next_cpu_attrs, false);
            if (status != MM_ACCESS_OK) {
                *out_ptr = NULL;
                if (out_cpu_attrs) {
                    *out_cpu_attrs = next_cpu_attrs;
                }
                return status;
            }
            if (next_ptr != first_ptr + offset) {
                needs_materialized_span = true;
                break;
            }
        }
    }

    if (needs_materialized_span && perm != MM_PROT_EXEC) {
        MM_DIRTY_SPAN* materialized = NULL;
        if (!mm_materialize_dirty_span(mgr, address, size, &materialized)) {
            *out_ptr = NULL;
            if (out_cpu_attrs) {
                *out_cpu_attrs = first_info.cpu_attrs;
            }
            return MM_ACCESS_UNMAPPED;
        }
        *out_ptr = materialized->data + (size_t)(address - materialized->base);
        if (out_cpu_attrs) {
            *out_cpu_attrs = first_info.cpu_attrs;
        }
        return MM_ACCESS_OK;
    }

    *out_ptr = first_ptr;
    if (out_cpu_attrs) {
        *out_cpu_attrs = first_cpu_attrs;
    }
    return MM_ACCESS_OK;
}

inline MM_ACCESS_STATUS mm_read_byte_checked(MEMORY_MANAGER* mgr, uint64_t address, uint8_t* out, uint32_t perm, uint32_t* out_cpu_attrs = NULL) {
    if (!out) {
        return MM_ACCESS_UNMAPPED;
    }

    uint8_t* ptr = NULL;
    MM_ACCESS_STATUS status = mm_get_ptr_checked_ex(mgr, address, perm, &ptr, out_cpu_attrs, false);
    if (status != MM_ACCESS_OK) {
        return status;
    }

    *out = *ptr;
    return MM_ACCESS_OK;
}

inline MM_ACCESS_STATUS mm_write_byte_checked(MEMORY_MANAGER* mgr, uint64_t address, uint8_t value, uint32_t* out_cpu_attrs = NULL) {
    uint8_t* ptr = NULL;
    MM_ACCESS_STATUS status = mm_get_ptr_checked_ex(mgr, address, MM_PROT_WRITE, &ptr, out_cpu_attrs, false);
    if (status != MM_ACCESS_OK) {
        return status;
    }

    *ptr = value;
    return MM_ACCESS_OK;
}

inline uint8_t* mm_translate(MEMORY_MANAGER* mgr, uint64_t address) {
    MM_ACCESS_INFO info = {};
    if (!mm_query(mgr, address, &info) || !info.mapped) {
        return NULL;
    }
    return info.ptr;
}

inline const uint8_t* mm_translate_const(const MEMORY_MANAGER* mgr, uint64_t address) {
    return mm_translate(const_cast<MEMORY_MANAGER*>(mgr), address);
}

inline bool mm_read_byte_with_perm(MEMORY_MANAGER* mgr, uint64_t address, uint8_t* out, uint32_t perm) {
    return mm_read_byte_checked(mgr, address, out, perm) == MM_ACCESS_OK;
}

inline bool mm_read_byte(MEMORY_MANAGER* mgr, uint64_t address, uint8_t* out) {
    return mm_read_byte_with_perm(mgr, address, out, MM_PROT_READ);
}

inline bool mm_read_exec_byte(MEMORY_MANAGER* mgr, uint64_t address, uint8_t* out) {
    return mm_read_byte_with_perm(mgr, address, out, MM_PROT_EXEC);
}

inline bool mm_write_byte(MEMORY_MANAGER* mgr, uint64_t address, uint8_t value) {
    return mm_write_byte_checked(mgr, address, value) == MM_ACCESS_OK;
}

inline uint8_t* mm_get_ptr_with_perm(MEMORY_MANAGER* mgr, uint64_t address, uint32_t perm) {
    uint8_t* ptr = NULL;
    return mm_get_ptr_checked_ex(mgr, address, perm, &ptr, NULL, false) == MM_ACCESS_OK ? ptr : NULL;
}

inline void mm_destroy(MEMORY_MANAGER* mgr) {
    if (!mgr) {
        return;
    }
    mm_clear_write_isolation_groups(mgr);
    mm_clear_write_isolation_exempt_ranges(mgr);
    for (size_t i = 0; i < mgr->region_count; i++) {
        mm_release_region(&mgr->regions[i]);
    }
    for (size_t i = 0; i < mgr->patch_count; i++) {
        if (mgr->patches[i].data) {
            CPUEAXH_FREE(mgr->patches[i].data);
        }
    }
    if (mgr->regions) {
        CPUEAXH_FREE(mgr->regions);
    }
    if (mgr->patches) {
        CPUEAXH_FREE(mgr->patches);
    }
    CPUEAXH_MEMSET(mgr, 0, sizeof(MEMORY_MANAGER));
}
