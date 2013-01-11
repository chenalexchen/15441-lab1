/** @file  server_define.h
 *  @brief define various necessary things for server
 *
 *  @author Chen Chen (chenche1)
 *  @bug no bug known
 */


#ifndef __SRV_DEF_H_
#define __SRV_DEF_H_

#include <netinet/in.h>
#include <netinet/ip.h>


#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#include "list.h"
#include "http.h"

/* define various macro */
#define TCP_PORT 9999
#define SSL_PORT 9998
#define BUF_IN_SIZE 4096
#define BUF_PROC_SIZE 2*BUF_IN_SIZE
#define BUF_OUT_SIZE 4096

#define BUF_HDR_SIZE 2048
#define TIMEOUT_TIME 10    /* in sec */
#define HASH_SIZE    0xff     /* size of hash size of client list */

#define DEFAULT_FD "../static_site/"
#define FILENAME_MAX_LEN 256

#define CGI_PREFIX                "/cgi/"
#define CGI_FD                    "../CGI/"
#define CGI_EXECUTABLE            "../flaskr/flaskr.py"
/* number of env */
#define CGI_ENV_CTR                   21
#define CGI_REMOTE_ADDR_LEN           32


/* struct declaration */
struct cli_cb_base;
typedef struct cli_cb_base cli_cb_base_t;
struct cli_cb_listen_tcp;
typedef struct cli_cb_listen_tcp cli_cb_listen_tcp_t;
struct cli_cb_tcp;
typedef struct cli_cb_tcp cli_cb_tcp_t;
struct cli_cb_ssl;
typedef struct cli_cb_ssl cli_cb_ssl_t;
struct cli_cb_cgi;
typedef struct cli_cb_cgi cli_cb_cgi_t;
struct cli_cb_listen_ssl;
typedef struct cli_cb_listen_ssl cli_cb_listen_ssl_t;

struct cli_cb_mthd{
        //  int (*new_connection)(cli_cb_base_t *cb);
        int (*recv)(cli_cb_base_t *cb);
        int (*parse)(cli_cb_base_t *cb);
        int (*handle_req_msg)(cli_cb_base_t *cb);
        int (*send)(cli_cb_base_t *cb);
        int (*process)(cli_cb_base_t *cb, int read_ready, int write_ready);
        //        int (*is_handle_req_msg_pending)(cli_cb_base_t *cb);
        int (*close)(cli_cb_base_t *cb);
        int (*close_read)(cli_cb_base_t *cb);
        int (*close_write)(cli_cb_base_t *cb);
        void (*destroy)(cli_cb_base_t *cb);

};

typedef struct cli_cb_mthd cli_cb_mthd_t;

enum cli_cb_type{
    LISTEN_TCP,
    CONN_TCP,
    LISTEN_SSL,
    CONN_SSL,
    CGI,
};


typedef enum cli_cb_type cli_cb_type_t;

struct cli_cb_base{
        cli_cb_type_t type;
                
        cli_cb_mthd_t mthd;
        struct list_head cli_rlink;
        struct list_head cli_wlink;
};



struct cli_cb_listen_tcp{
        cli_cb_base_t base;        
        int cli_fd;
};



struct cli_cb_tcp{
        cli_cb_base_t base;
        struct sockaddr_in cli_addr;

        int cli_fd;
                       
        char buf_in[BUF_IN_SIZE + 1];        /* recv'd str goes here */
        int buf_in_ctr;
        /* buf for processing pipelined reqs */   
        char buf_proc[BUF_PROC_SIZE + 1]; 
        int buf_proc_ctr;
        /* buf for output */
        char buf_out[BUF_OUT_SIZE + 1];
        int buf_out_ctr;

        req_msg_t *curr_req_msg;
        
        int rsrc_fd;                     /* fd for the resource file */
        struct stat statbuf;             /* statbuf for file */
        char *faddr;                     /* starting addr for mmap file */
        int fd_pos;                      /* pos in fd */

        cli_cb_base_t *cgi_parent;            /* the parent of cgi */
        int is_handle_cgi_pending;
        
        /* variables for parser */
        char *par_pos;
        char *par_next;
        char *par_msg_end;
        
        /* req msg list */
        struct list_head req_msg_list;      /* curr req msg to process */       
        int is_send_pending;
        int is_cgi_pending;
};

struct cli_cb_ssl{
        cli_cb_tcp_t tcp_base;        
        SSL *ssl;        
};

struct cli_cb_cgi{
        cli_cb_base_t base;
        cli_cb_base_t *cgi_parent;
        int cli_fd_read;
        int cli_fd_write;
};

struct cli_cb_listen_ssl{
        cli_cb_base_t base;        
        int cli_fd;        
};


int is_buf_empty(char *buf, int ctr);
void make_buf_empty(char *buf, int *ctr);

int parse_generic(cli_cb_base_t *cb);
void insert_req_msg(req_msg_t *msg, cli_cb_tcp_t *cb);
int parse_cgi_url(req_msg_t *msg);
void *strncpy_alloc(char *str, int len);


/* for cli_cb handling */
cli_cb_base_t *get_cli_cb(int cli_fd, int rw);
int init_cli_cb(cli_cb_base_t *cli_cb, cli_cb_base_t *parent_cb,
                struct sockaddr_in *addr, int cli_fd_read,
                int cli_fd_write,
                cli_cb_type_t type);
void free_cli_cb(cli_cb_base_t *cli_cb);


/* for srv function */
int establish_socket(void);
int select_wrapper(struct timeval *t);
int is_new_connection(int fd);
int create_new_connection(int fd);
int kill_connections(void);
int recv_wrapper(int fd);
int send_wrapper(int fd);
int process_request(void);

/* shutdown liso server */
void liso_shutdown(void);

/* daemonize the server */
int daemonize(char* lock_file);

/* cgi related functions */
int handle_cgi(req_msg_t *req_msg, cli_cb_base_t *cb);

#endif /* end of __SRV_DEF_H_ */
