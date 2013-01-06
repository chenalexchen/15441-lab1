/** @file err_code.h
 *  @brief define error code 
 *
 *  @author Chen Chen
 *  @bug no known bug
 */

#ifndef __ERR_CODE_H_
#define __ERR_CODE_H_


#define ERR_LOG_FILE         -0x100

#define ERR_ACCEPT_FAILURE   -0x101
#define ERR_NO_MEM           -0x102
#define ERR_CONNECTION_NOT_EXIST -0x103
#define ERR_SEND             -0x104
#define ERR_PARSE_MALFORMAT_REQ_MSG            -0x105
#define ERR_PARSE_REQ_MSG_TOO_LONG             -0x106
#define ERR_FSTAT            -0x107
#define ERR_MMAP             -0x108
#define ERR_SOCKET           -0x109
#define ERR_BIND             -0x10a
#define ERR_LISTEN           -0x10b
#define ERR_BUF              -0x10c
#define ERR_UNKNOWN_CLI_TYPE -0x10d
#define ERR_CLOSE_SOCKET     -0x10e
#define ERR_SSL_NEW          -0x10f
#define ERR_SSL_ACCEPT       -0x110
#define ERR_CLOSE_SSL_SOCKET -0x111
#define ERR_CGI_PARSE        -0x112
#define ERR_PIPE             -0x113
#define ERR_FORK             -0x114
#define ERR_EXEC             -0x115
#define ERR_INIT_CLI         -0x116
#define ERR_HDR_TOO_LONG     -0x117
#define ERR_CLOSE_FD         -0x118



#endif /* end of __ERR_CODE_H_ */
