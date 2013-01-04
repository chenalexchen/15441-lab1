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

#include "list.h"
#include "http.h"

/* define various macro */
#define ECHO_PORT 9999
#define BUF_IN_SIZE 4096
#define BUF_PROC_SIZE 2*BUF_IN_SIZE
#define BUF_OUT_SIZE 4096

#define BUF_HDR_SIZE 2048
#define TIMEOUT_TIME 1    /* in sec */
#define HASH_SIZE    0xff     /* size of hash size of client list */

#define DEFAULT_FD "../static_site/"
#define FILENAME_MAX_LEN 256

struct cli_cb{
    struct sockaddr_in cli_addr;
    int cli_fd;
    char buf_in[BUF_IN_SIZE + 1];        /* recv'd str goes here */
    char buf_proc[BUF_PROC_SIZE + 1]; /* buf for processing pipelined reqs */   
    char *buf_out;
    int buf_out_ctr;
    int buf_in_pos;
    int buf_proc_pos;

    char *par_pos;
    char *par_next;
    char *par_msg_end;

    struct list_head req_msg_list;                /* curr req msg to process */

    int handle_req_pending;
    struct list_head cli_link;
};

typedef struct cli_cb cli_cb_t;


int parse_cli_cb(cli_cb_t *cb);
void insert_req_msg(req_msg_t *msg, cli_cb_t *cb);
#endif /* end of __SRV_DEF_H_ */
