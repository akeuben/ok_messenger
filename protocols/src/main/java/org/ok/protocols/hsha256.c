/*Joshua Liu
A working implementation of SHA256 and HMAC
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>

typedef struct
{
    uint64_t length;
    uint32_t state[8];
    uint32_t curlen;
    uint8_t buf[64];
} Sha256Context;

#define SHA256_HASH_SIZE (256 / 8)

#define SHA256_BLOCK_SIZE 64

typedef struct
{
    uint8_t bytes[SHA256_HASH_SIZE];
} SHA256_HASH;

static uint32_t ror(uint32_t value, uint32_t bits)
{
    return ((value) >> (bits)) | ((value) << (32 - (bits)));
}

static uint32_t MIN(uint32_t x, uint32_t y)
{
    return ((x) < (y)) ? (x) : (y);
}

static void STORE32H(uint32_t x, uint8_t *y)
{
    (y)[0] = (uint8_t)(((x) >> 24) & 255);
    (y)[1] = (uint8_t)(((x) >> 16) & 255);
    (y)[2] = (uint8_t)(((x) >> 8) & 255);
    (y)[3] = (uint8_t)((x) & 255);
}

static uint32_t LOAD32H(uint8_t *y)
{
    return ((uint32_t)((y)[0] & 255) << 24) | ((uint32_t)((y)[1] & 255) << 16) |
           ((uint32_t)((y)[2] & 255) << 8) | ((uint32_t)((y)[3] & 255));
}

static void STORE64H(uint64_t x, uint8_t *y)
{
    (y)[0] = (uint8_t)(((x) >> 56) & 255);
    (y)[1] = (uint8_t)(((x) >> 48) & 255);
    (y)[2] = (uint8_t)(((x) >> 40) & 255);
    (y)[3] = (uint8_t)(((x) >> 32) & 255);
    (y)[4] = (uint8_t)(((x) >> 24) & 255);
    (y)[5] = (uint8_t)(((x) >> 16) & 255);
    (y)[6] = (uint8_t)(((x) >> 8) & 255);
    (y)[7] = (uint8_t)((x) & 255);
}

// The K array
static uint32_t K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};

#define BLOCK_SIZE 64

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  INTERNAL FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Various logical functions
static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return z ^ (x & (y ^ z));
}
static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x | y) & z) | (x & y);
}
static uint32_t SS(uint32_t x, uint32_t n)
{
    return ror((x), (n));
}
static uint32_t R(uint32_t x, uint32_t n)
{
    return ((x) & 0xFFFFFFFFUL) >> (n);
}
static uint32_t Sigma0(uint32_t x)
{
    return SS(x, 2) ^ SS(x, 13) ^ SS(x, 22);
}
static uint32_t Sigma1(uint32_t x)
{
    return SS(x, 6) ^ SS(x, 11) ^ SS(x, 25);
}
static uint32_t Gamma0(uint32_t x)
{
    return SS(x, 7) ^ SS(x, 18) ^ R(x, 3);
}
static uint32_t Gamma1(uint32_t x)
{
    return SS(x, 17) ^ SS(x, 19) ^ R(x, 10);
}

static void Sha256Round(uint32_t *S, uint32_t i, uint32_t *W)
{
    uint32_t t0 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + W[i];
    uint32_t t1 = Sigma0(S[0]) + Maj(S[0], S[1], S[2]);
    S[3] += t0;
    S[7] = t0 + t1;
    // printf("Round %02x\n", S[7]);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TransformFunction
//
//  Compress 512-bits
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static void TransformFunction(Sha256Context *Context, uint8_t *Buffer)
{
    uint32_t S[8];
    uint32_t W[64];
    uint32_t t;
    int i;

    // Copy state into S
    for (i = 0; i < 8; i++)
    {
        S[i] = Context->state[i];
    }

    // Copy the state into 512-bits into W[0..15]
    for (i = 0; i < 16; i++)
    {
        //  Buffer[i] = (uint8_t)Buffer[i] + (4 * i);
        // W[i] = LOAD32H(Buffer);
        W[i] = LOAD32H(Buffer + (4 * i));
    }
    for (i = 0; i < 16; i++)
    {
        printf("W Tr %02x\n", W[i]);
    }

    // Fill W[16..63]
    for (i = 16; i < 64; i++)
    {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }

    // Compress
    for (i = 0; i < 64; i++)
    {
        Sha256Round(S, i, W);
        t = S[7];
        S[7] = S[6];
        S[6] = S[5];
        S[5] = S[4];
        S[4] = S[3];
        S[3] = S[2];
        S[2] = S[1];
        S[1] = S[0];
        S[0] = t;
    }

    // Feedback
    for (i = 0; i < 8; i++)
    {
        Context->state[i] = Context->state[i] + S[i];
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha256Initialise
//
//  Initialises a SHA256 Context. Use this to initialise/reset a context.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void Sha256Initialise(Sha256Context *Context // [out]
)
{
    Context->curlen = 0;
    Context->length = 0;
    Context->state[0] = 0x6A09E667UL;
    Context->state[1] = 0xBB67AE85UL;
    Context->state[2] = 0x3C6EF372UL;
    Context->state[3] = 0xA54FF53AUL;
    Context->state[4] = 0x510E527FUL;
    Context->state[5] = 0x9B05688CUL;
    Context->state[6] = 0x1F83D9ABUL;
    Context->state[7] = 0x5BE0CD19UL;
    // for (int i = 0; i < 8; i++)
    // {
    //     printf("Init %02x\n", Context->state[i]);
    // }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha256Update
//
//  Adds data to the SHA256 context. This will process the data and update the
//  internal state of the context. Keep on calling this function until all the
//  data has been added. Then call Sha256Finalise to calculate the hash.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void Sha256Update(Sha256Context *Context, /* [in out]*/ uint8_t *Buffer, /* [in]*/ uint32_t BufferSize /* [in]*/)
{
    uint32_t n;
    if (Context->curlen > sizeof(Context->buf))
    {
        return;
    }

    while (BufferSize > 0)
    {
        if (Context->curlen == 0 && BufferSize >= BLOCK_SIZE)
        {
            TransformFunction(Context, (uint8_t *)Buffer);
            Context->length += BLOCK_SIZE * 8;
            Buffer = (uint8_t *)Buffer + BLOCK_SIZE;
            BufferSize -= BLOCK_SIZE;
        }
        else
        {
            for (int i = 0; i < sizeof(Buffer); i++)
            {
                printf("buff %02x\n", Buffer[i]);
            }
            n = MIN(BufferSize, (BLOCK_SIZE - Context->curlen));
            printf("N %02x\n", n);
            memcpy(Context->buf + Context->curlen, Buffer, (uint64_t)n);
            Context->curlen += n;
            Buffer = (uint8_t *)Buffer + n;
            BufferSize -= n;
            if (Context->curlen == BLOCK_SIZE)
            {
                TransformFunction(Context, Context->buf);
                Context->length += 8 * BLOCK_SIZE;
                Context->curlen = 0;
            }
        }
    }
    for (int i = 0; i < 8; i++)
    {
        printf("Upd %02x\n", Context->state[i]);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Sha256Finalise
//
//  Performs the final calculation of the hash and returns the digest (32 byte
//  buffer containing 256bit hash). After calling this, Sha256Initialised must
//  be used to reuse the context.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void Sha256Finalise(Sha256Context *Context, /*[in out]*/ SHA256_HASH *Digest /* [out]*/)
{
    int i;

    if (Context->curlen >= sizeof(Context->buf))
    {
        return;
    }

    // Increase the length of the message
    Context->length += Context->curlen * 8;

    // Append the '1' bit
    Context->buf[Context->curlen++] = (uint8_t)0x80;

    // if the length is currently above 56 bytes we append zeros
    // then compress.  Then we can fall back to padding zeros and length
    // encoding like normal.
    if (Context->curlen > 56)
    {
        while (Context->curlen < 64)
        {
            Context->buf[Context->curlen++] = (uint8_t)0;
        }
        TransformFunction(Context, Context->buf);
        Context->curlen = 0;
    }

    // Pad up to 56 bytes of zeroes
    while (Context->curlen < 56)
    {
        Context->buf[Context->curlen++] = (uint8_t)0;
    }

    // Store length
    STORE64H(Context->length, Context->buf + 56);
    TransformFunction(Context, Context->buf);

    // Copy output
    for (i = 0; i < 8; i++)
    {
        STORE32H(Context->state[i], Digest->bytes + (4 * i));
    }
}

void Sha256Calculate(uint8_t *Buffer, /* [in]*/ uint32_t BufferSize, /* [in]*/ SHA256_HASH *Digest /* [in]*/)
{
    Sha256Context context;

    Sha256Initialise(&context);
    Sha256Update(&context, Buffer, BufferSize);
    Sha256Finalise(&context, Digest);
}

// Concatenate X & Y, return hash.
static void *H(uint8_t *x, uint64_t xlen, uint8_t *y, uint64_t ylen, uint8_t *out, uint64_t outlen);

// Wrapper for sha256
static void *sha256(char *data, uint64_t datalen, uint8_t *out, uint64_t outlen);

uint64_t hmacSha256(char *key, uint64_t keylen, char *data, uint64_t datalen, uint8_t *out, uint64_t outlen)
{
    uint8_t k[SHA256_BLOCK_SIZE];
    uint8_t k_ipad[SHA256_BLOCK_SIZE];
    uint8_t k_opad[SHA256_BLOCK_SIZE];
    uint8_t ihash[SHA256_HASH_SIZE];
    uint8_t ohash[SHA256_HASH_SIZE];
    uint64_t sz;
    int i;
    for (i = 0; i < sizeof(k); i++)
    {
        k[i] = 0;
    }
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        k_ipad[i] = 0x36;
    }
    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        k_opad[i] = 0x5c;
    }

    if (keylen > SHA256_BLOCK_SIZE)
    {
        // If the key is larger than the hash algorithm's
        // block size, we must digest it first.
        sha256(key, keylen, k, sizeof(k));
    }
    else
    {
        for (i = 0; i < keylen; i++)
        {
            k[i] = key[i];
        }
        // memcpy(k, key, keylen);
    }

    for (i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        k_ipad[i] ^= k[i];
        k_opad[i] ^= k[i];
    }

    // Perform HMAC algorithm: ( https://tools.ietf.org/html/rfc2104 )
    //      `H(K XOR opad, H(K XOR ipad, data))`
    H(k_ipad, sizeof(k_ipad), data, datalen, ihash, sizeof(ihash));
    H(k_opad, sizeof(k_opad), ihash, sizeof(ihash), ohash, sizeof(ohash));

    sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
    memcpy(out, ohash, sz);
    return sz;
}

static void *H(uint8_t *x, uint64_t xlen, uint8_t *y, uint64_t ylen, uint8_t *out, uint64_t outlen)
{
    void *result;
    uint64_t buflen = (xlen + ylen);
    uint8_t *buf = (uint8_t *)malloc(buflen);

    memcpy(buf, x, xlen);
    memcpy(buf + xlen, y, ylen);
    result = sha256(buf, buflen, out, outlen);
    
    free(buf);
    return result;
}

static void *sha256(char *data, uint64_t datalen, uint8_t *out, uint64_t outlen)
{
    uint64_t sz;
    Sha256Context ctx;
    SHA256_HASH hash;

    Sha256Initialise(&ctx);
    Sha256Update(&ctx, data, datalen);
    for (int i = 0; i < sizeof(data); i++)
    {
        printf("data %02x\n", data[i]);
    }
    Sha256Finalise(&ctx, &hash);

    sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
    return memcpy(out, hash.bytes, sz);
}

int main()
{
    char *str_data = "hello";
    char *str_key = "keykey";
    uint8_t out[SHA256_HASH_SIZE];
    char out_str[SHA256_HASH_SIZE * 2 + 1];
    unsigned i;

    // Call hmac-sha256 function
    hmacSha256(str_key, strlen(str_key), str_data, strlen(str_data), out,
                sizeof(out));
    // Convert `out` to string with printf
    memset(&out_str, 0, sizeof(out_str));
    for (i = 0; i < sizeof(out); i++)
    {
        snprintf(&out_str[i * 2], 3, "%02x", out[i]);
    }

    // Print out the result
    printf("Message: %s\n", str_data);
    printf("Key: %s\n", str_key);
    printf("HMAC: %s\n", out_str);

    // This assertion fails if something went wrong
    assert(strncmp(out_str, "209800404ad6227356941d9b1fd44a610d178902db5e9ca2a25d8cf1f8ecaf12", SHA256_HASH_SIZE * 2) == 0);
    return 0;
}