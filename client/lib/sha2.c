/* * */

/* 作者：Aaron D.Gifford-http://www.aarongifford.com/ */
#include <string.h>	/* memcpy（）/memset（）或bcopy（）/bzero（） */
#include <assert.h>	/* assert（） */
#include "sha2.h"

#if HAVE_SYS_BYTEORDER_H
  #include <sys/byteorder.h>
#endif

/* *断言注释： */


/* **SHA-256/384/512机器体系结构定义**************** */
/* *字节顺序注释（_O）： */

#ifndef BYTE_ORDER
  #ifdef WIN32
    #define BYTE_ORDER BIG_ENDIAN
  #elif defined(_BIG_ENDIAN)
    #define BYTE_ORDER BIG_ENDIAN
  #elif defined(_LITTLE_ENDIAN)
    #define BYTE_ORDER LITTLE_ENDIAN
  #endif
#endif

#if !defined(BYTE_ORDER) || (BYTE_ORDER != LITTLE_ENDIAN && BYTE_ORDER != BIG_ENDIAN)
#error Define BYTE_ORDER to be equal to either LITTLE_ENDIAN or BIG_ENDIAN
#endif

/* *将以下类型2_*定义为上正确长度的类型 */
#ifdef SHA2_USE_INTTYPES_H

typedef uint8_t  sha2_byte;	/* 正好1个字节 */
typedef uint32_t sha2_word32;	/* 正好4个字节 */
typedef uint64_t sha2_word64;	/* 正好8个字节 */

#else /* SHA2_USE_INTTYPES_H */

typedef u_int8_t  sha2_byte;	/* 正好1个字节 */
typedef u_int32_t sha2_word32;	/* 正好4个字节 */
typedef u_int64_t sha2_word64;	/* 正好8个字节 */

#endif /* SHA2_USE_INTTYPES_H */


/* **SHA-256/384/512各种长度定义********************** */
/* 注：大多数都在sha2.h */
#define SHA256_SHORT_BLOCK_LEN	(SHA256_BLOCK_LEN - 8)
#define SHA384_SHORT_BLOCK_LEN	(SHA384_BLOCK_LEN - 16)
#define SHA512_SHORT_BLOCK_LEN	(SHA512_BLOCK_LEN - 16)


/* **ENDIAN反转宏****************************************** */
#if BYTE_ORDER == LITTLE_ENDIAN
#define REVERSE32(w,x)	{ \
	sha2_word32 tmp = (w); \
	tmp = (tmp >> 16) | (tmp << 16); \
	(x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
}
#define REVERSE64(w,x)	{ \
	sha2_word64 tmp = (w); \
	tmp = (tmp >> 32) | (tmp << 32); \
	tmp = ((tmp & 0xff00ff00ff00ff00ULL) >> 8) | \
	      ((tmp & 0x00ff00ff00ff00ffULL) << 8); \
	(x) = ((tmp & 0xffff0000ffff0000ULL) >> 16) | \
	      ((tmp & 0x0000ffff0000ffffULL) << 16); \
}
#endif /* 字节顺序==LITTLE_ENDIAN */

/* *用于将无符号64位整数n增量添加到 */
#define ADDINC128(w,n)	{ \
	(w)[0] += (sha2_word64)(n); \
	if ((w)[0] < (n)) { \
		(w)[1]++; \
	} \
}

/* *用于复制内存块和调零范围的宏 */
#if !defined(SHA2_USE_MEMSET_MEMCPY) && !defined(SHA2_USE_BZERO_BCOPY)
/* 如果未指定选项，则默认为memset（）/memcpy（） */
#define	SHA2_USE_MEMSET_MEMCPY	1
#endif
#if defined(SHA2_USE_MEMSET_MEMCPY) && defined(SHA2_USE_BZERO_BCOPY)
/* 如果定义了BOTH选项，则中止并出现错误 */
#error Define either SHA2_USE_MEMSET_MEMCPY or SHA2_USE_BZERO_BCOPY, not both!
#endif

#ifdef SHA2_USE_MEMSET_MEMCPY
#define MEMSET_BZERO(p,l)	memset((p), 0, (l))
#define MEMCPY_BCOPY(d,s,l)	memcpy((d), (s), (l))
#endif
#ifdef SHA2_USE_BZERO_BCOPY
#define MEMSET_BZERO(p,l)	bzero((p), (l))
#define MEMCPY_BCOPY(d,s,l)	bcopy((s), (d), (l))
#endif


/* **六个逻辑函数*************************************** */
/* *位移位和旋转（由六个SHA-XYZ逻辑函数使用： */
/* 右移（用于SHA-256、SHA-384和SHA-512）： */
#define R(b,x) 		((x) >> (b))
/* 32位向右旋转（用于SHA-256）： */
#define S32(b,x)	(((x) >> (b)) | ((x) << (32 - (b))))
/* 64位向右旋转（用于SHA-384和SHA-512）： */
#define S64(b,x)	(((x) >> (b)) | ((x) << (64 - (b))))

/* SHA-256、SHA-384和SHA-512中使用的六个逻辑函数中的两个： */
#define Ch(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* SHA-256中使用的六个逻辑函数中的四个： */
#define Sigma0_256(x)	(S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))
#define Sigma1_256(x)	(S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
#define sigma0_256(x)	(S32(7,  (x)) ^ S32(18, (x)) ^ R(3 ,   (x)))
#define sigma1_256(x)	(S32(17, (x)) ^ S32(19, (x)) ^ R(10,   (x)))

/* SHA-384和SHA-512中使用的六个逻辑函数中的四个： */
#define Sigma0_512(x)	(S64(28, (x)) ^ S64(34, (x)) ^ S64(39, (x)))
#define Sigma1_512(x)	(S64(14, (x)) ^ S64(18, (x)) ^ S64(41, (x)))
#define sigma0_512(x)	(S64( 1, (x)) ^ S64( 8, (x)) ^ R( 7,   (x)))
#define sigma1_512(x)	(S64(19, (x)) ^ S64(61, (x)) ^ R( 6,   (x)))

/* **内部功能原型************************************ */
/* 注意：这些不应直接从外部访问 */
void SHA512_Last(SHA512_CTX*);
void SHA256_Transform(SHA256_CTX*, const sha2_word32*);
void SHA512_Transform(SHA512_CTX*, const sha2_word64*);


/* **SHA-XYZ初始哈希值和常量*********************** */
/* SHA-256的哈希常量字K： */
const static sha2_word32 K256[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
	0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
	0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
	0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
	0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
	0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
	0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
	0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
	0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
	0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
	0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
	0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
	0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/* SHA-256的初始哈希值H： */
const static sha2_word32 sha256_initial_hash_value[8] = {
	0x6a09e667UL,
	0xbb67ae85UL,
	0x3c6ef372UL,
	0xa54ff53aUL,
	0x510e527fUL,
	0x9b05688cUL,
	0x1f83d9abUL,
	0x5be0cd19UL
};

/* SHA-384和SHA-512的哈希常量字K： */
const static sha2_word64 K512[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/* SHA-384的初始哈希值H */
const static sha2_word64 sha384_initial_hash_value[8] = {
	0xcbbb9d5dc1059ed8ULL,
	0x629a292a367cd507ULL,
	0x9159015a3070dd17ULL,
	0x152fecd8f70e5939ULL,
	0x67332667ffc00b31ULL,
	0x8eb44a8768581511ULL,
	0xdb0c2e0d64f98fa7ULL,
	0x47b5481dbefa4fa4ULL
};

/* SHA-512的初始哈希值H */
const static sha2_word64 sha512_initial_hash_value[8] = {
	0x6a09e667f3bcc908ULL,
	0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL,
	0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL,
	0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL,
	0x5be0cd19137e2179ULL
};


/* **沙-256：******************************************************** */
void SHA256_Init(SHA256_CTX* context) {
	if (context == (SHA256_CTX*)0) {
		return;
	}
	MEMCPY_BCOPY(context->state, sha256_initial_hash_value, SHA256_DIGEST_LEN);
	MEMSET_BZERO(context->buffer, SHA256_BLOCK_LEN);
	context->bitcount = 0;
}

#ifdef SHA2_UNROLL_TRANSFORM

/* 推出SHA-256圆形宏： */

#if BYTE_ORDER == LITTLE_ENDIAN

#define ROUND256_0_TO_15(a,b,c,d,e,f,g,h)	\
	REVERSE32(*data++, W256[j]); \
	T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + \
             K256[j] + W256[j]; \
	(d) += T1; \
	(h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
	j++


#else /* 字节顺序==LITTLE_ENDIAN */

#define ROUND256_0_TO_15(a,b,c,d,e,f,g,h)	\
	T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + \
	     K256[j] + (W256[j] = *data++); \
	(d) += T1; \
	(h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
	j++

#endif /* 字节顺序==LITTLE_ENDIAN */

#define ROUND256(a,b,c,d,e,f,g,h)	\
	s0 = W256[(j+1)&0x0f]; \
	s0 = sigma0_256(s0); \
	s1 = W256[(j+14)&0x0f]; \
	s1 = sigma1_256(s1); \
	T1 = (h) + Sigma1_256(e) + Ch((e), (f), (g)) + K256[j] + \
	     (W256[j&0x0f] += s1 + W256[(j+9)&0x0f] + s0); \
	(d) += T1; \
	(h) = T1 + Sigma0_256(a) + Maj((a), (b), (c)); \
	j++

void SHA256_Transform(SHA256_CTX* context, const sha2_word32* data) {
	sha2_word32	a, b, c, d, e, f, g, h, s0, s1;
	sha2_word32	T1, *W256;
	int		j;

	W256 = (sha2_word32*)context->buffer;

	/* 用prev初始化寄存器。中间值 */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do {
		/* 第0到15轮（展开）： */
		ROUND256_0_TO_15(a,b,c,d,e,f,g,h);
		ROUND256_0_TO_15(h,a,b,c,d,e,f,g);
		ROUND256_0_TO_15(g,h,a,b,c,d,e,f);
		ROUND256_0_TO_15(f,g,h,a,b,c,d,e);
		ROUND256_0_TO_15(e,f,g,h,a,b,c,d);
		ROUND256_0_TO_15(d,e,f,g,h,a,b,c);
		ROUND256_0_TO_15(c,d,e,f,g,h,a,b);
		ROUND256_0_TO_15(b,c,d,e,f,g,h,a);
	} while (j < 16);

	/* 现在剩下的64轮： */
	do {
		ROUND256(a,b,c,d,e,f,g,h);
		ROUND256(h,a,b,c,d,e,f,g);
		ROUND256(g,h,a,b,c,d,e,f);
		ROUND256(f,g,h,a,b,c,d,e);
		ROUND256(e,f,g,h,a,b,c,d);
		ROUND256(d,e,f,g,h,a,b,c);
		ROUND256(c,d,e,f,g,h,a,b);
		ROUND256(b,c,d,e,f,g,h,a);
	} while (j < 64);

	/* 计算当前中间哈希值 */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* 清理 */
	a = b = c = d = e = f = g = h = T1 = 0;
}

#else /* SHA2_UNROLL_TRANSFORM */

void SHA256_Transform(SHA256_CTX* context, const sha2_word32* data) {
	sha2_word32	a, b, c, d, e, f, g, h, s0, s1;
	sha2_word32	T1, T2, *W256;
	int		j;

	W256 = (sha2_word32*)context->buffer;

	/* 用prev初始化寄存器。中间值 */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do {
#if BYTE_ORDER == LITTLE_ENDIAN
		/* 转换为主机字节顺序时复制数据 */
		REVERSE32(*data++,W256[j]);
		/* 应用SHA-256压缩功能更新a..h */
		T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + W256[j];
#else /* 字节顺序==LITTLE_ENDIAN */
		/* 应用SHA-256压缩功能用副本更新a..h */
		T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + (W256[j] = *data++);
#endif /* 字节顺序==LITTLE_ENDIAN */
		T2 = Sigma0_256(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 16);

	do {
		/* 消息块扩展的一部分： */
		s0 = W256[(j+1)&0x0f];
		s0 = sigma0_256(s0);
		s1 = W256[(j+14)&0x0f];
		s1 = sigma1_256(s1);

		/* 应用SHA-256压缩功能更新a..h */
		T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] +
		     (W256[j&0x0f] += s1 + W256[(j+9)&0x0f] + s0);
		T2 = Sigma0_256(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 64);

	/* 计算当前中间哈希值 */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* 清理 */
	a = b = c = d = e = f = g = h = T1 = T2 = 0;
}

#endif /* SHA2_UNROLL_TRANSFORM */

void SHA256_Update(SHA256_CTX* context, const sha2_byte *data, size_t len) {
	unsigned int	freespace, usedspace;

	if (len == 0) {
		/* 没有数据的调用是有效的-我们什么都不做 */
		return;
	}

	/* 卫生检查： */
	assert(context != (SHA256_CTX*)0 && data != (sha2_byte*)0);

	usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LEN;
	if (usedspace > 0) {
		/* 计算缓冲区中有多少可用空间 */
		freespace = SHA256_BLOCK_LEN - usedspace;

		if (len >= freespace) {
			/* 完全填充缓冲区并进行处理 */
			MEMCPY_BCOPY(&context->buffer[usedspace], data, freespace);
			context->bitcount += freespace << 3;
			len -= freespace;
			data += freespace;
			SHA256_Transform(context, (sha2_word32*)context->buffer);
		} else {
			/* 缓冲区尚未满 */
			MEMCPY_BCOPY(&context->buffer[usedspace], data, len);
			context->bitcount += len << 3;
			/* 清理： */
			usedspace = freespace = 0;
			return;
		}
	}
	while (len >= SHA256_BLOCK_LEN) {
		/* 处理尽可能多的完整块 */
		SHA256_Transform(context, (sha2_word32*)data);
		context->bitcount += SHA256_BLOCK_LEN << 3;
		len -= SHA256_BLOCK_LEN;
		data += SHA256_BLOCK_LEN;
	}
	if (len > 0) {
		/* 还有剩余的，留着吧 */
		MEMCPY_BCOPY(context->buffer, data, len);
		context->bitcount += len << 3;
	}
	/* 清理： */
	usedspace = freespace = 0;
}

void SHA256_Final(sha2_byte digest[], SHA256_CTX* context) {
	sha2_word32	*d = (sha2_word32*)digest;
	unsigned int	usedspace;

	/* 卫生检查： */
	assert(context != (SHA256_CTX*)0);

	/* 如果没有传递摘要缓冲区，我们就不必这么做： */
	if (digest != (sha2_byte*)0) {
		usedspace = (context->bitcount >> 3) % SHA256_BLOCK_LEN;
#if BYTE_ORDER == LITTLE_ENDIAN
		/* 转换FROM主机字节顺序 */
		REVERSE64(context->bitcount,context->bitcount);
#endif
		if (usedspace > 0) {
			/* 以1位开始填充： */
			context->buffer[usedspace++] = 0x80;

			if (usedspace <= SHA256_SHORT_BLOCK_LEN) {
				/* 为上一次转换设置： */
				MEMSET_BZERO(&context->buffer[usedspace], SHA256_SHORT_BLOCK_LEN - usedspace);
			} else {
				if (usedspace < SHA256_BLOCK_LEN) {
					MEMSET_BZERO(&context->buffer[usedspace], SHA256_BLOCK_LEN - usedspace);
				}
				/* 执行倒数第二个变换： */
				SHA256_Transform(context, (sha2_word32*)context->buffer);

				/* 以及最后一次转换的设置： */
				MEMSET_BZERO(context->buffer, SHA256_SHORT_BLOCK_LEN);
			}
		} else {
			/* 为上一次转换设置： */
			MEMSET_BZERO(context->buffer, SHA256_SHORT_BLOCK_LEN);

			/* 以1位开始填充： */
			*context->buffer = 0x80;
		}
		/* 设置位计数： */
		memcpy(&(context->buffer[SHA256_SHORT_BLOCK_LEN]), &(context->bitcount), sizeof(sha2_word64));

		/* 最终变换： */
		SHA256_Transform(context, (sha2_word32*)context->buffer);

#if BYTE_ORDER == LITTLE_ENDIAN
		{
			/* 转换为主机字节顺序 */
			int	j;
			for (j = 0; j < 8; j++) {
				REVERSE32(context->state[j],context->state[j]);
				*d++ = context->state[j];
			}
		}
#else
		MEMCPY_BCOPY(d, context->state, SHA256_DIGEST_LEN);
#endif
	}

	/* 清理状态数据： */
	MEMSET_BZERO(context, sizeof(*context));
	usedspace = 0;
}

/* **沙512：******************************************************** */
void SHA512_Init(SHA512_CTX* context) {
	if (context == (SHA512_CTX*)0) {
		return;
	}
	MEMCPY_BCOPY(context->state, sha512_initial_hash_value, SHA512_DIGEST_LEN);
	MEMSET_BZERO(context->buffer, SHA512_BLOCK_LEN);
	context->bitcount[0] = context->bitcount[1] =  0;
}

#ifdef SHA2_UNROLL_TRANSFORM

/* 推出SHA-512圆形宏： */
#if BYTE_ORDER == LITTLE_ENDIAN

#define ROUND512_0_TO_15(a,b,c,d,e,f,g,h)	\
	REVERSE64(*data++, W512[j]); \
	T1 = (h) + Sigma1_512(e) + Ch((e), (f), (g)) + \
             K512[j] + W512[j]; \
	(d) += T1, \
	(h) = T1 + Sigma0_512(a) + Maj((a), (b), (c)), \
	j++


#else /* 字节顺序==LITTLE_ENDIAN */

#define ROUND512_0_TO_15(a,b,c,d,e,f,g,h)	\
	T1 = (h) + Sigma1_512(e) + Ch((e), (f), (g)) + \
             K512[j] + (W512[j] = *data++); \
	(d) += T1; \
	(h) = T1 + Sigma0_512(a) + Maj((a), (b), (c)); \
	j++

#endif /* 字节顺序==LITTLE_ENDIAN */

#define ROUND512(a,b,c,d,e,f,g,h)	\
	s0 = W512[(j+1)&0x0f]; \
	s0 = sigma0_512(s0); \
	s1 = W512[(j+14)&0x0f]; \
	s1 = sigma1_512(s1); \
	T1 = (h) + Sigma1_512(e) + Ch((e), (f), (g)) + K512[j] + \
             (W512[j&0x0f] += s1 + W512[(j+9)&0x0f] + s0); \
	(d) += T1; \
	(h) = T1 + Sigma0_512(a) + Maj((a), (b), (c)); \
	j++

void SHA512_Transform(SHA512_CTX* context, const sha2_word64* data) {
	sha2_word64	a, b, c, d, e, f, g, h, s0, s1;
	sha2_word64	T1, *W512 = (sha2_word64*)context->buffer;
	int		j;

	/* 用prev初始化寄存器。中间值 */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do {
		ROUND512_0_TO_15(a,b,c,d,e,f,g,h);
		ROUND512_0_TO_15(h,a,b,c,d,e,f,g);
		ROUND512_0_TO_15(g,h,a,b,c,d,e,f);
		ROUND512_0_TO_15(f,g,h,a,b,c,d,e);
		ROUND512_0_TO_15(e,f,g,h,a,b,c,d);
		ROUND512_0_TO_15(d,e,f,g,h,a,b,c);
		ROUND512_0_TO_15(c,d,e,f,g,h,a,b);
		ROUND512_0_TO_15(b,c,d,e,f,g,h,a);
	} while (j < 16);

	/* 现在剩下的79轮比赛： */
	do {
		ROUND512(a,b,c,d,e,f,g,h);
		ROUND512(h,a,b,c,d,e,f,g);
		ROUND512(g,h,a,b,c,d,e,f);
		ROUND512(f,g,h,a,b,c,d,e);
		ROUND512(e,f,g,h,a,b,c,d);
		ROUND512(d,e,f,g,h,a,b,c);
		ROUND512(c,d,e,f,g,h,a,b);
		ROUND512(b,c,d,e,f,g,h,a);
	} while (j < 80);

	/* 计算当前中间哈希值 */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* 清理 */
	a = b = c = d = e = f = g = h = T1 = 0;
}

#else /* SHA2_UNROLL_TRANSFORM */

void SHA512_Transform(SHA512_CTX* context, const sha2_word64* data) {
	sha2_word64	a, b, c, d, e, f, g, h, s0, s1;
	sha2_word64	T1, T2, *W512 = (sha2_word64*)context->buffer;
	int		j;

	/* 用prev初始化寄存器。中间值 */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do {
#if BYTE_ORDER == LITTLE_ENDIAN
		/* 转换为主机字节顺序 */
		REVERSE64(*data++, W512[j]);
		/* 应用SHA-512压缩功能更新a..h */
		T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] + W512[j];
#else /* 字节顺序==LITTLE_ENDIAN */
		/* 应用SHA-512压缩功能用副本更新a..h */
		T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] + (W512[j] = *data++);
#endif /* 字节顺序==LITTLE_ENDIAN */
		T2 = Sigma0_512(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 16);

	do {
		/* 消息块扩展的一部分： */
		s0 = W512[(j+1)&0x0f];
		s0 = sigma0_512(s0);
		s1 = W512[(j+14)&0x0f];
		s1 =  sigma1_512(s1);

		/* 应用SHA-512压缩功能更新a..h */
		T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] +
		     (W512[j&0x0f] += s1 + W512[(j+9)&0x0f] + s0);
		T2 = Sigma0_512(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 80);

	/* 计算当前中间哈希值 */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* 清理 */
	a = b = c = d = e = f = g = h = T1 = T2 = 0;
}

#endif /* SHA2_UNROLL_TRANSFORM */

void SHA512_Update(SHA512_CTX* context, const sha2_byte *data, size_t len) {
	unsigned int	freespace, usedspace;

	if (len == 0) {
		/* 没有数据的调用是有效的-我们什么都不做 */
		return;
	}

	/* 卫生检查： */
	assert(context != (SHA512_CTX*)0 && data != (sha2_byte*)0);

	usedspace = (context->bitcount[0] >> 3) % SHA512_BLOCK_LEN;
	if (usedspace > 0) {
		/* 计算缓冲区中有多少可用空间 */
		freespace = SHA512_BLOCK_LEN - usedspace;

		if (len >= freespace) {
			/* 完全填充缓冲区并进行处理 */
			MEMCPY_BCOPY(&context->buffer[usedspace], data, freespace);
			ADDINC128(context->bitcount, freespace << 3);
			len -= freespace;
			data += freespace;
			SHA512_Transform(context, (sha2_word64*)context->buffer);
		} else {
			/* 缓冲区尚未满 */
			MEMCPY_BCOPY(&context->buffer[usedspace], data, len);
			ADDINC128(context->bitcount, len << 3);
			/* 清理： */
			usedspace = freespace = 0;
			return;
		}
	}
	while (len >= SHA512_BLOCK_LEN) {
		/* 处理尽可能多的完整块 */
		SHA512_Transform(context, (sha2_word64*)data);
		ADDINC128(context->bitcount, SHA512_BLOCK_LEN << 3);
		len -= SHA512_BLOCK_LEN;
		data += SHA512_BLOCK_LEN;
	}
	if (len > 0) {
		/* 还有剩余的，留着吧 */
		MEMCPY_BCOPY(context->buffer, data, len);
		ADDINC128(context->bitcount, len << 3);
	}
	/* 清理： */
	usedspace = freespace = 0;
}

void SHA512_Last(SHA512_CTX* context) {
	unsigned int	usedspace;

	usedspace = (context->bitcount[0] >> 3) % SHA512_BLOCK_LEN;
#if BYTE_ORDER == LITTLE_ENDIAN
	/* 转换FROM主机字节顺序 */
	REVERSE64(context->bitcount[0],context->bitcount[0]);
	REVERSE64(context->bitcount[1],context->bitcount[1]);
#endif
	if (usedspace > 0) {
		/* 以1位开始填充： */
		context->buffer[usedspace++] = 0x80;

		if (usedspace <= SHA512_SHORT_BLOCK_LEN) {
			/* 为上一次转换设置： */
			MEMSET_BZERO(&context->buffer[usedspace], SHA512_SHORT_BLOCK_LEN - usedspace);
		} else {
			if (usedspace < SHA512_BLOCK_LEN) {
				MEMSET_BZERO(&context->buffer[usedspace], SHA512_BLOCK_LEN - usedspace);
			}
			/* 执行倒数第二个变换： */
			SHA512_Transform(context, (sha2_word64*)context->buffer);

			/* 以及最后一次转换的设置： */
			MEMSET_BZERO(context->buffer, SHA512_BLOCK_LEN - 2);
		}
	} else {
		/* 准备进行最终转换： */
		MEMSET_BZERO(context->buffer, SHA512_SHORT_BLOCK_LEN);

		/* 以1位开始填充： */
		*context->buffer = 0x80;
	}
	/* 存储输入数据的长度（以位为单位）： */
	memcpy(&(context->buffer[SHA512_SHORT_BLOCK_LEN]),   &(context->bitcount[1]), sizeof(sha2_word64));
	memcpy(&(context->buffer[SHA512_SHORT_BLOCK_LEN+8]), &(context->bitcount[0]), sizeof(sha2_word64));

	/* 最终变换： */
	SHA512_Transform(context, (sha2_word64*)context->buffer);
}

void SHA512_Final(sha2_byte digest[], SHA512_CTX* context) {
	sha2_word64	*d = (sha2_word64*)digest;

	/* 卫生检查： */
	assert(context != (SHA512_CTX*)0);

	/* 如果没有传递摘要缓冲区，我们就不必这么做： */
	if (digest != (sha2_byte*)0) {
		SHA512_Last(context);

		/* 保存哈希数据以进行输出： */
#if BYTE_ORDER == LITTLE_ENDIAN
		{
			/* 转换为主机字节顺序 */
			int	j;
			for (j = 0; j < 8; j++) {
				REVERSE64(context->state[j],context->state[j]);
				*d++ = context->state[j];
			}
		}
#else
		MEMCPY_BCOPY(d, context->state, SHA512_DIGEST_LEN);
#endif
	}

	/* 归零状态数据 */
	MEMSET_BZERO(context, sizeof(*context));
}


/* **SHA-384：******************************************************** */
void SHA384_Init(SHA384_CTX* context) {
	if (context == (SHA384_CTX*)0) {
		return;
	}
	MEMCPY_BCOPY(context->state, sha384_initial_hash_value, SHA512_DIGEST_LEN);
	MEMSET_BZERO(context->buffer, SHA384_BLOCK_LEN);
	context->bitcount[0] = context->bitcount[1] = 0;
}

void SHA384_Update(SHA384_CTX* context, const sha2_byte* data, size_t len) {
	SHA512_Update((SHA512_CTX*)context, data, len);
}

void SHA384_Final(sha2_byte digest[], SHA384_CTX* context) {
	sha2_word64	*d = (sha2_word64*)digest;

	/* 卫生检查： */
	assert(context != (SHA384_CTX*)0);

	/* 如果没有传递摘要缓冲区，我们就不必这么做： */
	if (digest != (sha2_byte*)0) {
		SHA512_Last((SHA512_CTX*)context);

		/* 保存哈希数据以进行输出： */
#if BYTE_ORDER == LITTLE_ENDIAN
		{
			/* 转换为主机字节顺序 */
			int	j;
			for (j = 0; j < 6; j++) {
				REVERSE64(context->state[j],context->state[j]);
				*d++ = context->state[j];
			}
		}
#else
		MEMCPY_BCOPY(d, context->state, SHA384_DIGEST_LEN);
#endif
	}

	/* 归零状态数据 */
	MEMSET_BZERO(context, sizeof(*context));
}
