/*
 * Compressed stream unpacker.
 * Produces identical output to the aPLib decompressor.
 *
 * Bounded: never reads past the source or writes outside the
 * destination. Returns the number of bytes produced, or 0 if the
 * stream is malformed or does not fit.
 */

#include "depack.h"
#include "poly_section.h"

/* stream reader state */
struct StreamCtx {
  const unsigned char *src;
  const unsigned char *src_end;
  unsigned char *dst;
  unsigned char *dst_start;
  unsigned char *dst_end;
  unsigned int bits;
  unsigned int avail;
  unsigned int bad;
};

/* next source byte; flags the stream as bad when exhausted */
static unsigned int pull_byte(struct StreamCtx *ctx)
{
  if (ctx->src >= ctx->src_end) {
    ctx->bad = 1;
    return 0;
  }
  return *ctx->src++;
}

/* pull one bit from the stream */
static unsigned int pull_bit(struct StreamCtx *ctx)
{
  unsigned int b;

  if (ctx->avail == 0) {
    ctx->bits = pull_byte(ctx);
    ctx->avail = 8;
  }

  b = (ctx->bits >> 7) & 1;
  ctx->bits <<= 1;
  ctx->avail--;

  return b;
}

/* decode a gamma2 value (an exhausted stream reads as zero bits and ends it) */
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

/* append one byte to the output */
static void put_byte(struct StreamCtx *ctx, unsigned int v)
{
  if (ctx->dst >= ctx->dst_end) {
    ctx->bad = 1;
    return;
  }
  *ctx->dst++ = (unsigned char)v;
}

/* copy len bytes from (dst - offset) to dst */
static void copy_match(struct StreamCtx *ctx, unsigned int offset, unsigned int len)
{
  unsigned int k;

  if (offset == 0 ||
      offset > (unsigned int)(ctx->dst - ctx->dst_start) ||
      len    > (unsigned int)(ctx->dst_end - ctx->dst)) {
    ctx->bad = 1;
    return;
  }
  for (k = 0; k < len; k++) {
    *ctx->dst = *(ctx->dst - offset);
    ctx->dst++;
  }
}

LOADER_FN_SECTION(".aP_depack")
unsigned int aP_depack(const void *source, unsigned int srclen,
                       void *destination, unsigned int dstlen)
{
  struct StreamCtx ctx;
  unsigned int prev_offset, last_was_match;
  unsigned int offset, length;
  int running;
  unsigned int nibble;

  ctx.src = (const unsigned char *)source;
  ctx.src_end = ctx.src + srclen;
  ctx.dst = (unsigned char *)destination;
  ctx.dst_start = ctx.dst;
  ctx.dst_end = ctx.dst + dstlen;
  ctx.avail = 0;
  ctx.bits = 0;
  ctx.bad = 0;

  prev_offset = (unsigned int)-1;
  last_was_match = 0;
  running = 1;

  /* literal first byte */
  put_byte(&ctx, pull_byte(&ctx));

  while (running && !ctx.bad) {
    /* bit 0: literal */
    if (!pull_bit(&ctx)) {
      put_byte(&ctx, pull_byte(&ctx));
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

        offset = (offset << 8) | pull_byte(&ctx);
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
      nibble = pull_byte(&ctx);
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
      copy_match(&ctx, offset, 1);
    } else {
      put_byte(&ctx, 0x00);
    }

    last_was_match = 0;
  }

  if (ctx.bad) return 0;

  return (unsigned int)(ctx.dst - ctx.dst_start);
}