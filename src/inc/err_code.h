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

#endif /* end of __ERR_CODE_H_ */
