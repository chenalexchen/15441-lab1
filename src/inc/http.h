/** @file http.h
 *  @brief define struct for http protocol
 *
 *  @author Chen Chen
 *  @bug no bug known
 */


#ifndef __HTTP_H_
#define __HTTP_H_

#include "list.h"


#define REQ_END_STR   "\r\n\r\n"
#define LINE_END_STR  "\r\n"
#define FS_ROOT       "/"

enum req_mthd{
    OPTIONS = 0,
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    TRACE,
    CONNECT,
    EXT,
};


struct req_line{
    enum req_mthd req;
    char *url;
    char *ver;
};

struct msg_hdr{
    char *field_name;
    char *field_value;
    struct list_head msg_hdr_link;
};

struct req_msg{
    struct req_line req_line;
    struct list_head msg_hdr_list;
    struct list_head req_msg_link;
    char *msg_body;
    
    /* some booking field */
    int msg_body_len;
};


typedef struct req_line req_line_t;
typedef struct msg_hdr msg_hdr_t;
typedef struct req_msg req_msg_t;



void init_req_msg(req_msg_t *msg);
void init_msg_hdr(msg_hdr_t *hdr);

void insert_msg_hdr(msg_hdr_t *hdr, req_msg_t *msg);

void free_req_msg(req_msg_t *msg);



#endif /* end of __HTTP_H_ */
