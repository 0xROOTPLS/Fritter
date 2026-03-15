/*
 * Compressed stream unpacker.
 * Produces identical output to the aPLib decompressor.
 */

#include "depack.h"

/* stream reader state */
struct StreamCtx {
  const unsigned char *src;
  unsigned char *dst;
  unsigned int bits;
  unsigned int avail;
};

/* pull one bit from the stream */
static unsigned int pull_bit(struct StreamCtx *ctx)
{
  unsigned int b;

  if (ctx->avail == 0) {
    ctx->bits = *ctx->src++;
    ctx->avail = 8;
  }

  b = (ctx->bits >> 7) & 1;
  ctx->bits <<= 1;
  ctx->avail--;

  return b;
}

/* decode a gamma2 value */
static unsigned int decode_gamma(struct StreamCtx *ctx)
{
  unsigned int val = 1;

  for (;;) {
    val = (val << 1) | pull_bit(ctx);
    if (!pull_bit(ctx))
      break;
  }

  return val;
}

/* copy len bytes from (dst - offset) to dst */
static void copy_match(struct StreamCtx *ctx, unsigned int offset, unsigned int len)
{
  unsigned int k;
  for (k = 0; k < len; k++) {
    *ctx->dst = *(ctx->dst - offset);
    ctx->dst++;
  }
}

unsigned int aP_depack(const void *source, void *destination)
{
  struct StreamCtx ctx;
  unsigned int prev_offset, last_was_match;
  unsigned int offset, length;
  int running;
  unsigned int nibble;

  ctx.src = (const unsigned char *)source;
  ctx.dst = (unsigned char *)destination;
  ctx.avail = 0;
  ctx.bits = 0;

  prev_offset = (unsigned int)-1;
  last_was_match = 0;
  running = 1;

  /* literal first byte */
  *ctx.dst++ = *ctx.src++;

  while (running) {
    /* bit 0: literal */
    if (!pull_bit(&ctx)) {
      *ctx.dst++ = *ctx.src++;
      last_was_match = 0;
      continue;
    }

    /* bit 1,0: long match */
    if (!pull_bit(&ctx)) {
      offset = decode_gamma(&ctx);

      if (last_was_match == 0 && offset == 2) {
        /* re-use previous offset */
        offset = prev_offset;
        length = decode_gamma(&ctx);
        copy_match(&ctx, offset, length);
      } else {
        if (last_was_match == 0)
          offset -= 3;
        else
          offset -= 2;

        offset = (offset << 8) | *ctx.src++;
        length = decode_gamma(&ctx);

        if (offset >= 32000) length++;
        if (offset >= 1280)  length++;
        if (offset < 128)    length += 2;

        copy_match(&ctx, offset, length);
        prev_offset = offset;
      }
      last_was_match = 1;
      continue;
    }

    /* bit 1,1,0: short match */
    if (!pull_bit(&ctx)) {
      nibble = *ctx.src++;
      length = 2 + (nibble & 1);
      offset = nibble >> 1;

      if (offset == 0) {
        running = 0;
      } else {
        copy_match(&ctx, offset, length);
      }

      prev_offset = offset;
      last_was_match = 1;
      continue;
    }

    /* bit 1,1,1: single-byte match or zero */
    offset = 0;
    nibble = 4;
    while (nibble--) {
      offset = (offset << 1) | pull_bit(&ctx);
    }

    if (offset != 0) {
      *ctx.dst = *(ctx.dst - offset);
      ctx.dst++;
    } else {
      *ctx.dst++ = 0x00;
    }

    last_was_match = 0;
  }

  return (unsigned int)(ctx.dst - (unsigned char *)destination);
}
