

#ifndef ZTN_MESSAGE_H
#define ZTN_MESSAGE_H 1

/* SPA消息格式验证功能。 */
int validate_cmd_msg(const char *msg);
int validate_access_msg(const char *msg);
int validate_nat_access_msg(const char *msg);
int validate_proto_port_spec(const char *msg);

#endif /* ZTN_MESSAGE_H */

/* **EOF** */
