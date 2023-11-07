
#include "ztn_common.h"

#if !HAVE_STRLCAT
/* *将src附加到大小为siz的字符串dst（与strncat不同，siz是 */
size_t
strlcat(char *dst, const char *src, size_t siz)
{
	register char *d = dst;
	register const char *s = src;
	register size_t n = siz;
	size_t dlen;

	/* 找到dst的末尾并调整剩余字节，但不要超过末尾 */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* 计数不包括NUL */
}
#endif

/* **EOF** */
