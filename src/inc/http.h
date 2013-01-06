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


struct cgi_arg{
        char *arg;
        struct list_head arg_link;
};

typedef struct cgi_arg cgi_arg_t;

struct cgi_url{
        struct list_head arg_list;        
        int arg_ctr;
};

typedef struct cgi_url cgi_url_t;


struct req_line{
        enum req_mthd req;
        char *url;
        char *ver;
        cgi_url_t cgi_url;
};

struct msg_hdr{
    char *field_name;
    char *field_value;
    struct list_head msg_hdr_link;
};

struct req_msg{
        struct req_line req_line;
        struct list_head msg_hdr_list;
        int msg_hdr_ctr;
        
        char *msg_body;
        
        /* some booking field */
        int msg_body_len;

        struct list_head req_msg_link;
};


typedef struct req_line req_line_t;
typedef struct msg_hdr msg_hdr_t;
typedef struct req_msg req_msg_t;



void init_req_msg(req_msg_t *msg);
void init_msg_hdr(msg_hdr_t *hdr);

void insert_msg_hdr(msg_hdr_t *hdr, req_msg_t *msg);

void free_req_msg(req_msg_t *msg);

int init_cgi_url(cgi_url_t *url);
void clear_cgi_url(cgi_url_t *url);
int init_cgi_arg(cgi_arg_t *arg);
void clear_cgi_arg(cgi_arg_t *arg);
void insert_cgi_arg(cgi_arg_t *arg, cgi_url_t *url);

#endif /* end of __HTTP_H_ */
