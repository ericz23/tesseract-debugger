/*
 * parser.cpp — Toy binary packet parser with 4 intentional bugs.
 *
 * Wire format:
 *   [0..1]  magic      : uint16_t  must be 0xCAFE
 *   [2]     type       : uint8_t   0x01 = BASIC, 0x02 = EXTENDED
 *   [3]     flags      : uint8_t   bit 0 = has_extra
 *   [4]     name_len   : uint8_t   length of the name string that follows
 *   [5..5+name_len-1]  name bytes
 *   after name:
 *     num_items  : uint8_t   number of 4-byte items
 *     items[]    : num_items × uint32_t
 *   if type == EXTENDED:
 *     offset     : uint8_t   index into a 16-entry lookup table
 *   if flags & 0x01 (has_extra):
 *     extra_ptr is set, then unconditionally dereferenced — BUG 3
 *
 * BUGS (intentional, for fuzzing research):
 *   Bug 1 — Stack buffer overflow  : name_len not checked before memcpy into 32-byte buf
 *   Bug 2 — Integer overflow → heap: num_items * 4 computed as uint8_t, wraps, undersized malloc
 *   Bug 3 — Null pointer deref     : extra_ptr only set when has_extra flag is set, always deref'd
 *   Bug 4 — Out-of-bounds read     : offset used without range check to index lookup[16]
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

// Exposed for the harness.
extern "C" int parse(const uint8_t *data, size_t size);

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static constexpr uint16_t MAGIC         = 0xCAFE;
static constexpr uint8_t  TYPE_BASIC    = 0x01;
static constexpr uint8_t  TYPE_EXTENDED = 0x02;
static constexpr uint8_t  FLAG_HAS_EXTRA = 0x01;

static const uint32_t lookup[16] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB,
    0xCC, 0xDD, 0xEE, 0xFF,
};

struct ParsedPacket {
    uint8_t  type;
    uint8_t  flags;
    char     name[32];   // fixed-size — Bug 1 lives here
    uint32_t *items;     // heap-allocated — Bug 2 lives here
    uint8_t  num_items;
    const char *extra;   // Bug 3: may be null even when dereferenced
    uint32_t lookup_val; // Bug 4: filled from an unchecked offset
};

// Bug 1: stack buffer overflow.
// name_len can be up to 255 but the destination is only 32 bytes.
static bool parse_name(const uint8_t *src, uint8_t name_len, char dst[32]) {
    // BUG 1: no bounds check on name_len before copying into 32-byte dst
    memcpy(dst, src, name_len);
    dst[name_len] = '\0'; // also writes past the end when name_len >= 32
    return true;
}

// Bug 2: integer overflow leading to heap overflow.
// num_items and sizeof(uint32_t)=4 are both small, but the multiplication is
// done in uint8_t arithmetic, so values ≥ 64 wrap around.
static uint32_t *alloc_items(uint8_t num_items) {
    // BUG 2: uint8_t overflow — e.g. 128 * 4 = 0 (mod 256) → malloc(0)
    uint8_t byte_count = num_items * 4u;
    return static_cast<uint32_t *>(malloc(byte_count ? byte_count : 1));
}

// Fill items — writes num_items * 4 bytes regardless of how much was allocated.
static void fill_items(uint32_t *buf, uint8_t num_items, const uint8_t *src) {
    for (uint8_t i = 0; i < num_items; ++i) {
        uint32_t v;
        memcpy(&v, src + i * 4, sizeof(v));
        buf[i] = v; // BUG 2 trigger: writes past malloc'd region when overflow occurred
    }
}

// ---------------------------------------------------------------------------
// Top-level parser
// ---------------------------------------------------------------------------

extern "C" int parse(const uint8_t *data, size_t size) {
    if (size < 5) return -1;

    // Check magic
    uint16_t magic;
    memcpy(&magic, data, 2);
    if (magic != MAGIC) return -1;

    uint8_t type  = data[2];
    uint8_t flags = data[3];

    if (type != TYPE_BASIC && type != TYPE_EXTENDED) return -1;

    uint8_t name_len = data[4];
    size_t  cursor   = 5;

    if (cursor + name_len > size) return -1;

    ParsedPacket pkt{};
    pkt.type  = type;
    pkt.flags = flags;

    // Bug 1: name_len unchecked against sizeof(pkt.name)
    parse_name(data + cursor, name_len, pkt.name);
    cursor += name_len;

    if (cursor + 1 > size) return -1;

    uint8_t num_items = data[cursor++];
    if (cursor + num_items * 4u > size) return -1;

    pkt.num_items = num_items;
    pkt.items     = alloc_items(num_items); // Bug 2: undersized allocation possible
    if (!pkt.items) return -1;

    fill_items(pkt.items, num_items, data + cursor); // Bug 2: heap overflow here
    cursor += static_cast<size_t>(num_items) * 4;

    // Bug 3: set extra only when flag is present, but always dereference below
    const char *extra_data = nullptr;
    if (flags & FLAG_HAS_EXTRA) {
        // Normally we'd read from the packet; for simplicity use a static string.
        extra_data = "extra!";
    }
    // BUG 3: unconditional dereference — crashes when flag was NOT set
    pkt.extra = extra_data;
    (void)pkt.extra[0]; // null deref when extra_data == nullptr

    // Bug 4: extended type reads an offset into lookup[] without range check
    if (type == TYPE_EXTENDED) {
        if (cursor + 1 > size) { free(pkt.items); return -1; }
        uint8_t offset = data[cursor++];
        // BUG 4: offset can be 0..255, but lookup has only 16 entries
        pkt.lookup_val = lookup[offset];
    }

    free(pkt.items);
    return 0;
}
