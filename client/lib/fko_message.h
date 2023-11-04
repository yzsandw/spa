

#ifndef FKO_MESSAGE_H
#define FKO_MESSAGE_H 1

/* SPA消息格式验证功能。 */
int validate_cmd_msg(const char *msg);
int validate_access_msg(const char *msg);
int validate_nat_access_msg(const char *msg);
int validate_proto_port_spec(const char *msg);

#endif /* FKO_MESSAGE_H */

/* **EOF** */
