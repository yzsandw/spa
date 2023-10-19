/**
 * \file server/access.h
 *
 * \brief Header file for fwknopd access.c.
 */

#ifndef ACCESS_H
#define ACCESS_H

#define PROTO_TCP   6
#define PROTO_UDP   17

/**
 * \def ACCESS_BUF_LEN
 *
 * \brief 允许大小为123.123.123.123/255.255.255.255的字符串
 */
#define ACCESS_BUF_LEN  33

/**
 * \def MAX_DEPTH
 *
 * \brief 递归深度
 *
 * 不会递归超过3个深度.
*/
#define MAX_DEPTH 3

/* 函数原型
*/

/**
 * \brief 加载access.conf文件
 *
 *
 * \param opts指向要填充的fko_srv_options_t结构的指针
 * \param ccess_filename指向要加载的文件名的指针
 * \param depth指向当前深度的指针。这从0开始，每次递归都会递增
 *
 * \return return返回错误状态，或EXIT_SUCCESS
 *
 */
int parse_access_file(fko_srv_options_t *opts, char *access_filename, int *depth);

/**
 * \brief 加载文件夹中的access.conf文件
 *
 *此函数不会递归到子文件夹中，而是调用parse_access_file
 *对于每个包含的文件。此函数不会增加深度int。
 *
 */
int parse_access_folder(fko_srv_options_t *opts, char *access_folder, int *depth);

/**
 * \brief 访问节的基本验证
 *
 *这是一个基本检查，以确保至少有一个访问节
 *填充了“source”变量，并且此函数仅
 *在处理完所有access.conf文件后调用。这允许
 *%include_folder处理以继续处理
 *具有无法访问的.conf文件。附加更强
 *验证是在acc_data_is_valid（）中完成的，但此函数
 *仅当从中解析出“SOURCE”变量时调用

 *文件。
 *
 * \param acc指向保存访问节的acc_stanza_t结构的指针
 *
 * \return 返回错误状态或EXIT_SUCCESS
 *
 */
int valid_access_stanzas(acc_stanza_t *acc);

/**
 * \brief Compares address lists
 *
 *此函数在链表中查找匹配的IP地址。
 *主要用于为传入的SPA数据包。
 *
 * \param 要比较的ip地址
 *
 * \return 在匹配时返回true
 *
 */
int compare_addr_list(acc_int_list_t *source_list, const uint32_t ip);

/**
 * \brief Check for a proto-port string
 *
 *取一个proto/port字符串（或多个逗号分隔的字符串）并检查
 *将它们与给定访问节的列表进行比较。
 *
 *\param acc指向保存访问节的acc_stanza_t结构的指针
 *\param port_str指向要查找的端口字符串的指针
 *
 * \return return如果允许则返回true
 *
 */
int acc_check_port_access(acc_stanza_t *acc, char *port_str);

/**
 * \brief 将当前配置转储到stdout
 *
 * \param opts指向服务器选项结构的指针
 *
 */
void dump_access_list(const fko_srv_options_t *opts);

/**
 * \brief 将proto/port字符串扩展为访问proto-port结构的列表。
 *
 *这采用逗号分隔的proto/port值的单个字符串，并将它们添加到链接列表中
 *
 * \param plist指向acc_port_list_t的双指针，用于保存proto/ports
 * \param plist_str指向proto/port值列表的指针
 *
 * \return 如果成功则返回true
 *
 */
int expand_acc_port_list(acc_port_list_t **plist, char *plist_str);

/**
 * \brief 将do_acc_stanza_init设置为true，这将启用free_acc_stancas（）
 *
 */
void enable_acc_stanzas_init(void);

/**
 * \brief 所有访问节的可用内存
 *
 * \param opts指向fko_srv_options_t的指针，该指针包含要释放的访问节链
 *
 */
void free_acc_stanzas(fko_srv_options_t *opts);

/**
 * \brief 释放端口列表
 *
 * \param plist指向acc_port_list_t以释放指针
 *
 */
void free_acc_port_list(acc_port_list_t *plist);

#ifdef HAVE_C_UNIT_TESTS
int register_ts_access(void);
#endif

#endif /* ACCESS_H */

/***EOF***/
