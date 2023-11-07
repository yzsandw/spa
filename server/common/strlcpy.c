
#include "ztn_common.h"

#if !HAVE_STRLCPY
/* *将src复制到大小为siz的字符串dst。最多siz-1个字符 */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	register char *d = dst;
	register const char *s = src;
	register size_t n = siz;

	/* 复制尽可能多的字节 */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* dst中没有足够的空间，添加NUL并遍历src的其余部分 */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL终止dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* 计数不包括NUL */
}
#endif

/* **EOF** */
