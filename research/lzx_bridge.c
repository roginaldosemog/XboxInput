/* In-memory adapter for libmspack (LGPL-2.1), linked as a separate analysis DLL.
 * Does not read files or access console hardware. No codec code is vendored.
 * Reference: emoose/idaxex 3rdparty/lzx.cpp (Xenia BSD wrapper).
 */
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "mspack.h"
#include "lzx.h"

typedef struct { unsigned char *data; size_t size, offset; } Buffer;
static int buffer_read(struct mspack_file *file, void *out, int count) {
    Buffer *b = (Buffer *)file;
    if (count < 0) return -1;
    size_t n = (size_t)count;
    if (n > b->size - b->offset) n = b->size - b->offset;
    memcpy(out, b->data + b->offset, n);
    b->offset += n;
    return (int)n;
}
static int buffer_write(struct mspack_file *file, void *in, int count) {
    Buffer *b = (Buffer *)file;
    if (count < 0 || (size_t)count > b->size - b->offset) return -1;
    memcpy(b->data + b->offset, in, (size_t)count);
    b->offset += (size_t)count;
    return count;
}
static void *buffer_alloc(struct mspack_system *sys, size_t size) {
    (void)sys;
    return calloc(size, 1);
}
static void buffer_copy(void *src, void *dst, size_t size) { memcpy(dst, src, size); }

__declspec(dllexport) int xboxinput_lzx_decode(
    const void *src, size_t src_size, void *dst, size_t dst_size, int window_bits) {
    if (!src || !dst || !src_size || !dst_size || src_size > INT_MAX ||
        dst_size > INT_MAX || window_bits < 15 || window_bits > 21) return -1;
    struct mspack_system sys = {0};
    sys.read = buffer_read;
    sys.write = buffer_write;
    sys.alloc = buffer_alloc;
    sys.free = free;
    sys.copy = buffer_copy;
    Buffer input = {(unsigned char *)src, src_size, 0};
    Buffer output = {(unsigned char *)dst, dst_size, 0};
    struct lzxd_stream *stream = lzxd_init(&sys, (struct mspack_file *)&input,
        (struct mspack_file *)&output, window_bits, 0, 0x8000, (off_t)dst_size, 0);
    if (!stream) return -2;
    int code = lzxd_decompress(stream, (off_t)dst_size);
    lzxd_free(stream);
    return code ? code : (output.offset == dst_size ? 0 : -3);
}
