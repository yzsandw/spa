
#include <stdio.h>
#include <signal.h>

#ifdef WIN32
  #include <conio.h>
#else
  #include <termios.h>
#endif

#include "spanop_common.h"
#include "getpasswd.h"
#include "utils.h"

/*
这段代码定义了一些与密码处理相关的常量和宏。下面是对每个常量和宏的详细解释：

    PW_BUFSIZE：密码或加密密钥中可以包含的最大字符数。

    PW_BREAK_CHAR：Ctrl-C字符的ASCII码，用于中断密码输入。

    PW_BS_CHAR：退格字符的ASCII码，用于删除密码输入中的一个字符。

    PW_LF_CHAR：换行字符\n的ASCII码。

    PW_CR_CHAR：回车字符\r的ASCII码。

    PW_CLEAR_CHAR：Ctrl-U字符的ASCII码，用于清除密码输入。

    ARRAY_FIRST_ELT_ADR(t)：宏，用于获取数组t的第一个元素的地址。

    ARRAY_LAST_ELT_ADR(t)：宏，用于获取数组t的最后一个元素的地址。

这些常量和宏可以方便地在密码处理相关的代码中使用，例如控制密码输入的格式、处理特殊字符以及获取数组的首尾元素地址等操作。
对于密码输入，可以使用这些常量和宏进行一些特定的处理，例如捕获用户输入的中断信号、删除输入的错误字符、清除输入的内容等。
同时，通过宏ARRAY_FIRST_ELT_ADR和ARRAY_LAST_ELT_ADR，可以方便地获取数组的首尾元素地址，进行遍历或其他操作。

这些常量和宏的存在使得密码输入和处理的代码更加清晰和可维护，同时提供了一些常用的工具和功能，方便开发人员进行密码相关功能的实现。


*/
#define PW_BUFSIZE              128                 /*!< Maximum number of chars an encryption key or a password can contain */

#define PW_BREAK_CHAR           0x03                /*!< Ascii code for the Ctrl-C char */
#define PW_BS_CHAR              0x08                /*!< Ascii code for the backspace char */
#define PW_LF_CHAR              0x0A                /*!< Ascii code for the \n char */
#define PW_CR_CHAR              0x0D                /*!< Ascii code for the \r char */
#define PW_CLEAR_CHAR           0x15                /*!< Ascii code for the Ctrl-U char */

#define ARRAY_FIRST_ELT_ADR(t)  &((t)[0])           /*!< Macro to get the first element of an array */
#define ARRAY_LAST_ELT_ADR(t)   &((t)[sizeof(t)-1]) /*!< Macro to get the last element of an array */

/**
 * @brief Read a password from a stream object
 *
 * @param stream Pointer to a FILE object that identifies an input stream.
 *
 * @return The password buffer or NULL if not set
 */

/*
这段代码是一个函数 read_passwd_from_stream，用于从输入流中读取密码并返回密码字符串。

函数首先定义了一个静态数组 password，大小为 PW_BUFSIZE，并初始化为全零。然后定义了一个指针 ptr，指向 password 数组的第一个元素。

接下来，函数检查输入流是否为 NULL，如果是，则直接返回 password。然后进入循环读取字符的逻辑。

在 Windows 平台上，使用 _getch() 函数来读取字符；在其他平台上，使用 getc() 函数读取字符。
循环条件是当读取到 EOF、换行符 PW_LF_CHAR 或中断信号 PW_BREAK_CHAR 时退出。

在循环体内，首先判断读取到的字符是否是退格字符 PW_BS_CHAR。如果是，并且指针 ptr 不指向 password 数组的第一个元素，
将指针向前移动一个位置。

然后判断读取到的字符是否是清除密码的控制字符 PW_CLEAR_CHAR。如果是，将指针 ptr 指向 password 数组的第一个元素，
即重新开始输入密码。

接下来判断指针 ptr 是否还没有达到 password 数组的最后一个元素。如果是，则将读取到的字符存储在 ptr 指向的位置，
并将指针 ptr 向后移动一个位置。

最后，如果读取到的字符是中断信号 PW_BREAK_CHAR，则将 password 数组的第一个元素置为空字符。否则，在循环结束后，
将指针 ptr 指向的位置置为空字符，即将密码字符串正确地以空字符结尾。

最后，函数返回 password 数组，即读取到的密码字符串。

该函数的作用是从输入流中安全地读取密码，并返回密码字符串。它通过处理特定的控制字符和限制密码长度来确保密码的安全性。


*/
static char *
read_passwd_from_stream(FILE *stream)
{
    static char     password[PW_BUFSIZE] = {0};
    int             c;
    char           *ptr;

    ptr = ARRAY_FIRST_ELT_ADR(password);

    if(stream == NULL)
        return password;
#ifdef WIN32
    while((c = _getch()) != PW_CR_CHAR)
#else
    while( ((c = getc(stream)) != EOF) && (c != PW_LF_CHAR) && (c != PW_BREAK_CHAR) )
#endif
    {
        /* 处理退格键，避免退得太远。 */
        if (c == PW_BS_CHAR)
        {
            if (ptr != ARRAY_FIRST_ELT_ADR(password))
                ptr--;
        }

        /* 处理 Ctrl-U，清除密码输入并重新开始 */
        else if (c == PW_CLEAR_CHAR)
            ptr = ARRAY_FIRST_ELT_ADR(password);

        /* 填充密码缓冲区直到最后一个字符前。
         * 最后一个字符用来添加空字符终止字符串。 */
        else if (ptr < ARRAY_LAST_ELT_ADR(password))
        {
            *ptr++ = c;
        }

        /* 丢弃字符 */
        else;
    }

    /* 如果检测到 CTRL-C 字符，我们将放弃密码 */
    if (c == PW_BREAK_CHAR)
        password[0] = '\0';

    /* 否则我们在这里添加空字符终止字符串。之前已经处理过溢出，
     * 所以我们可以不用担心地添加字符 */
    else
        *ptr = '\0';

    return password;
}



/*
2023/7/20 15:25:27

这段代码是一个函数 getpasswd，用于从文件描述符或标准输入流中安全地读取密码，并返回密码字符串。

函数首先定义了指针变量 ptr 和文件指针 fp。在 Windows 平台上，它会将文件描述符强制设置为标准输入流（stdin）。

如果传入的文件描述符有效，函数会尝试从该文件描述符创建一个输入流。如果创建成功，则将文件指针 fp 设置为该输入流；
否则，函数会返回 NULL。

如果文件描述符无效，则函数会打开一个新的输入流。它会获取终端设备的信息，并禁用回显、信号处理和规范模式。
然后，在终端上输出提示信息。

接下来，函数调用 read_passwd_from_stream(fp) 从输入流中读取密码，并将返回的密码字符串赋值给指针变量 ptr。

在 Windows 平台上，函数会输出回车换行符（CR-LF）。

在其他平台上，如果传入的文件描述符无效，则函数会重置终端设置，并在终端上输出换行符。然后，关闭输入流。

最后，函数返回密码字符串的指针变量 ptr。

该函数的作用是从文件描述符或标准输入流中安全地读取密码，并返回密码字符串。
它通过处理终端设备的设置和调用 read_passwd_from_stream 函数来保证密码的安全性。


*/
char*
getpasswd(const char *prompt, int fd)
{
    char           *ptr = NULL;
    FILE           *fp  = NULL;

#ifndef WIN32
    sigset_t        sig, old_sig;
    struct termios  ts;
    tcflag_t        old_c_lflag = 0;
#else
	fd = 0;
#endif

    if (FD_IS_VALID(fd))
    {
        fp = fdopen(fd, "r");
        if (fp == NULL)
        {
            log_msg(LOG_VERBOSITY_ERROR, "getpasswd() - "
                "Unable to create a stream from the file descriptor : %s",
                strerror(errno));
            return(NULL);
        }
    }



#ifndef WIN32
    sigset_t        sig, old_sig;
    struct termios  ts;
    tcflag_t        old_c_lflag = 0;
#else
	/* 在 Windows 上强制使用标准输入(stdin)。 */
	fd = 0;
#endif

    /* 如果提供了有效的文件描述符，我们尝试从它创建一个流 */
    if (FD_IS_VALID(fd))
    {
        fp = fdopen(fd, "r");
        if (fp == NULL)
        {
           log_msg(LOG_VERBOSITY_ERROR, "getpasswd() - "
                "Unable to create a stream from the file descriptor : %s",
                strerror(errno));
            return(NULL);
        }
    }

#ifndef WIN32
    /* 否则，我们将打开一个新的流 */
    else
    {
        if((fp = fopen(ctermid(NULL), "r+")) == NULL)
            return(NULL);

        setbuf(fp, NULL);

        /* 阻塞 SIGINT 和 SIGTSTP 信号，并保存原始的信号掩码。 */
        sigemptyset(&sig);
        sigaddset(&sig, SIGINT);
        sigaddset(&sig, SIGTSTP);
        sigprocmask(SIG_BLOCK, &sig, &old_sig);

        /*
        * 在我们进行以下操作后保存当前终端状态，以便之后恢复：
        *   - 禁用字符回显到终端
        *   - 禁用信号生成
        *   - 禁用规范模式（逐行读取输入模式）
        */
        tcgetattr(fileno(fp), &ts);
        old_c_lflag = ts.c_lflag;
        ts.c_lflag &= ~(ECHO | ICANON | ISIG);
        tcsetattr(fileno(fp), TCSAFLUSH, &ts);

        fputs(prompt, fp);
    }
#else
    _cputs(prompt);
#endif
    /* 读取密码 */
    ptr = read_passwd_from_stream(fp);

#ifdef WIN32
    /* 在 Windows 中，它将是 CR-LF */
    _putch(PW_CR_CHAR);
    _putch(PW_LF_CHAR);
#else
    if(! FD_IS_VALID(fd))
    {
        /* 重置终端设置 */
        fputs("\n", fp);
        ts.c_lflag = old_c_lflag;
        tcsetattr(fileno(fp), TCSAFLUSH, &ts);
    }
#endif

    fclose(fp);

    return (ptr);
}


/*
2023/7/20 15:26:27

这段代码是一个函数 get_key_file，用于从配置文件中获取密码。函数使用给定的配置文件路径 key_file 打开文件，并按行读取文件内容。

在循环中，函数逐行读取文件，并处理每一行的内容。首先，函数会跳过空白字符和等号，并在遇到注释、空行或分号时继续读取下一行。

然后，函数会检查是否找到了与指定的目标匹配的行。它通过比较配置选项 options->spa_server_str 与当前行的前缀来确定是否匹配。
如果找到了匹配的行，则函数会提取行中的密码信息，并将其存储在参数 key 中。

最后，函数会关闭文件指针，并检查是否成功获取了密码。如果没有获取到密码，则会返回 0；否则，会返回 1。
同时，函数还会设置参数 key_len 来指示密码的长度。

该函数的作用是从配置文件中获取密码信息，并返回密码及其长度。

*/
int
get_key_file(char *key, int *key_len, const char *key_file,
    ztn_ctx_t ctx, const ztn_cli_options_t *options)
{
    FILE           *pwfile_ptr;
    unsigned int    numLines = 0, i = 0, found_dst;

    char            conf_line_buf[MAX_LINE_LEN] = {0};
    char            tmp_char_buf[MAX_LINE_LEN]  = {0};
    char           *lptr;

    memset(key, 0x00, MAX_KEY_LEN+1);

    if ((pwfile_ptr = fopen(key_file, "r")) == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "Could not open config file: %s", key_file);
        return 0;
    }

    while ((fgets(conf_line_buf, MAX_LINE_LEN, pwfile_ptr)) != NULL)
{
    numLines++;
    conf_line_buf[MAX_LINE_LEN-1] = '\0';
    lptr = conf_line_buf;

    memset(tmp_char_buf, 0x0, MAX_LINE_LEN);

    while (*lptr == ' ' || *lptr == '\t' || *lptr == '=')
        lptr++;

    /* 跳过注释和空行。 */
    if (*lptr == '#' || *lptr == '\n' || *lptr == '\r' || *lptr == '\0' || *lptr == ';')
        continue;

    /* 寻找类似 "<SPA目标IP>: <密码>" 的行 - 这允许在同一个文件中放置多个密钥，
    * 客户端将为我们正在联系的SPA服务器引用匹配的密钥 */
    found_dst = 1;
    for (i=0; i < strlen(options->spa_server_str); i++)
        if (*lptr++ != options->spa_server_str[i])
            found_dst = 0;

    if (!found_dst)
        continue;

    if (*lptr == ':')
        lptr++;
    else
        continue;

    /* 跳过空白直到我们得到密码 */
    while (*lptr == ' ' || *lptr == '\t' || *lptr == '=')
        lptr++;

    i = 0;
    while (*lptr != '\0' && *lptr != '\n') {
        key[i] = *lptr;
        lptr++;
        i++;
    }
    key[i] = '\0';
}


    fclose(pwfile_ptr);

    if (key[0] == '\0') {
        log_msg(LOG_VERBOSITY_ERROR, "Could not get key for IP: %s from: %s",
            options->spa_server_str, key_file);
        return 0;
    }

    *key_len = strlen(key);

    return 1;
}

/***EOF***/
