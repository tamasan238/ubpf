/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>

#include "dp-packet.h"

// from util.h
void *
xrealloc(void *p, size_t size)
{
    p = realloc(p, size ? size : 1);
    if (p == NULL) {
        exit(1);
    }
    return p;
}


void *
xmalloc(size_t size)
{
    void *p = malloc(size ? size : 1);
    if (p == NULL) {
        exit(1);
    }
    return p;
}
#define OVS_NOT_REACHED() abort()
// end

/* Initializes 'b' as a DPDK dp-packet, which must have been allocated from a
 * DPDK memory pool. */
void
dp_packet_init_dpdk(struct dp_packet *b)
{
    b->source = DPBUF_DPDK;
}

static void
dp_packet_copy__(struct dp_packet *b, uint8_t *new_base,
                 size_t new_headroom, size_t new_tailroom)
{
    const uint8_t *old_base = dp_packet_base(b);
    size_t old_headroom = dp_packet_headroom(b);
    size_t old_tailroom = dp_packet_tailroom(b);
    size_t copy_headroom = MIN(old_headroom, new_headroom);
    size_t copy_tailroom = MIN(old_tailroom, new_tailroom);

    memcpy(&new_base[new_headroom - copy_headroom],
           &old_base[old_headroom - copy_headroom],
           copy_headroom + dp_packet_size(b) + copy_tailroom);
}

/* Reallocates 'b' so that it has exactly 'new_headroom' and 'new_tailroom'
 * bytes of headroom and tailroom, respectively. */
static void
dp_packet_resize__(struct dp_packet *b, size_t new_headroom, size_t new_tailroom)
{
    void *new_base, *new_data;
    size_t new_allocated;

    new_allocated = new_headroom + dp_packet_size(b) + new_tailroom;

    switch (b->source) {
        case DPBUF_DPDK:
            OVS_NOT_REACHED();

        case DPBUF_MALLOC:
            if (new_headroom == dp_packet_headroom(b)) {
                new_base = xrealloc(dp_packet_base(b), new_allocated);
            } else {
                new_base = xmalloc(new_allocated);
                dp_packet_copy__(b, new_base, new_headroom, new_tailroom);
                free(dp_packet_base(b));
            }
            break;

        case DPBUF_STACK:
            OVS_NOT_REACHED();

        case DPBUF_AFXDP:
            OVS_NOT_REACHED();

        case DPBUF_STUB:
            b->source = DPBUF_MALLOC;
            new_base = xmalloc(new_allocated);
            dp_packet_copy__(b, new_base, new_headroom, new_tailroom);
            break;

        default:
            OVS_NOT_REACHED();
    }

    dp_packet_set_allocated(b, new_allocated);
    dp_packet_set_base(b, new_base);

    new_data = (char *) new_base + new_headroom;
    if (dp_packet_data(b) != new_data) {
        dp_packet_set_data(b, new_data);
    }
}

/* Ensures that 'b' has room for at least 'size' bytes at its tail end,
 * reallocating and copying its data if necessary.  Its headroom, if any, is
 * preserved. */
void
dp_packet_prealloc_tailroom(struct dp_packet *b, size_t size)
{
    if (size > dp_packet_tailroom(b)) {
        dp_packet_resize__(b, dp_packet_headroom(b), MAX(size, 64));
    }
}

/* Ensures that 'b' has room for at least 'size' bytes at its head,
 * reallocating and copying its data if necessary.  Its tailroom, if any, is
 * preserved. */
void
dp_packet_prealloc_headroom(struct dp_packet *b, size_t size)
{
    if (size > dp_packet_headroom(b)) {
        dp_packet_resize__(b, MAX(size, 64), dp_packet_tailroom(b));
    }
}

/* Shifts all of the data within the allocated space in 'b' by 'delta' bytes.
 * For example, a 'delta' of 1 would cause each byte of data to move one byte
 * forward (from address 'p' to 'p+1'), and a 'delta' of -1 would cause each
 * byte to move one byte backward (from 'p' to 'p-1'). */
void
dp_packet_shift(struct dp_packet *b, int delta)
{
    ovs_assert(delta > 0 ? delta <= dp_packet_tailroom(b)
                         : delta < 0 ? -delta <= dp_packet_headroom(b)
                                     : true);

    if (delta != 0) {
        char *dst = (char *) dp_packet_data(b) + delta;
        memmove(dst, dp_packet_data(b), dp_packet_size(b));
        dp_packet_set_data(b, dst);
    }
}

/* Appends 'size' bytes of data to the tail end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * new data, which is left uninitialized. */
void *
dp_packet_put_uninit(struct dp_packet *b, size_t size)
{
    void *p;
    dp_packet_prealloc_tailroom(b, size);
    p = dp_packet_tail(b);
    dp_packet_set_size(b, dp_packet_size(b) + size);
    return p;
}

/* Appends 'size' zeroed bytes to the tail end of 'b'.  Data in 'b' is
 * reallocated and copied if necessary.  Returns a pointer to the first byte of
 * the data's location in the dp_packet. */
void *
dp_packet_put_zeros(struct dp_packet *b, size_t size)
{
    void *dst = dp_packet_put_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

/* Appends the 'size' bytes of data in 'p' to the tail end of 'b'.  Data in 'b'
 * is reallocated and copied if necessary.  Returns a pointer to the first
 * byte of the data's location in the dp_packet. */
void *
dp_packet_put(struct dp_packet *b, const void *p, size_t size)
{
    void *dst = dp_packet_put_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* Reserves 'size' bytes of headroom so that they can be later allocated with
 * dp_packet_push_uninit() without reallocating the dp_packet. */
void
dp_packet_reserve(struct dp_packet *b, size_t size)
{
    ovs_assert(!dp_packet_size(b));
    dp_packet_prealloc_tailroom(b, size);
    dp_packet_set_data(b, (char*)dp_packet_data(b) + size);
}

/* Reserves 'headroom' bytes at the head and 'tailroom' at the end so that
 * they can be later allocated with dp_packet_push_uninit() or
 * dp_packet_put_uninit() without reallocating the dp_packet. */
void
dp_packet_reserve_with_tailroom(struct dp_packet *b, size_t headroom,
                                size_t tailroom)
{
    ovs_assert(!dp_packet_size(b));
    dp_packet_prealloc_tailroom(b, headroom + tailroom);
    dp_packet_set_data(b, (char*)dp_packet_data(b) + headroom);
}

/* Prefixes 'size' bytes to the head end of 'b', reallocating and copying its
 * data if necessary.  Returns a pointer to the first byte of the data's
 * location in the dp_packet.  The new data is left uninitialized. */
void *
dp_packet_push_uninit(struct dp_packet *b, size_t size)
{
    dp_packet_prealloc_headroom(b, size);
    dp_packet_set_data(b, (char*)dp_packet_data(b) - size);
    dp_packet_set_size(b, dp_packet_size(b) + size);
    return dp_packet_data(b);
}

/* Prefixes 'size' zeroed bytes to the head end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * data's location in the dp_packet. */
void *
dp_packet_push_zeros(struct dp_packet *b, size_t size)
{
    void *dst = dp_packet_push_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

/* Copies the 'size' bytes starting at 'p' to the head end of 'b', reallocating
 * and copying its data if necessary.  Returns a pointer to the first byte of
 * the data's location in the dp_packet. */
void *
dp_packet_push(struct dp_packet *b, const void *p, size_t size)
{
    void *dst = dp_packet_push_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

static inline void
dp_packet_adjust_layer_offset(uint16_t *offset, int increment)
{
    if (*offset != UINT16_MAX) {
        *offset += increment;
    }
}

/* Adjust the size of the l2_5 portion of the dp_packet, updating the l2
 * pointer and the layer offsets.  The caller is responsible for
 * modifying the contents. */
void *
dp_packet_resize_l2_5(struct dp_packet *b, int increment)
{
    if (increment >= 0) {
        dp_packet_push_uninit(b, increment);
    } else {
        dp_packet_pull(b, -increment);
    }

    /* Adjust layer offsets after l2_5. */
    dp_packet_adjust_layer_offset(&b->l3_ofs, increment);
    dp_packet_adjust_layer_offset(&b->l4_ofs, increment);

    return dp_packet_data(b);
}

/* Adjust the size of the l2 portion of the dp_packet, updating the l2
 * pointer and the layer offsets.  The caller is responsible for
 * modifying the contents. */
void *
dp_packet_resize_l2(struct dp_packet *b, int increment)
{
    dp_packet_resize_l2_5(b, increment);
    dp_packet_adjust_layer_offset(&b->l2_5_ofs, increment);
    return dp_packet_data(b);
}
