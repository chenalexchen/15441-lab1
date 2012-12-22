/** @file  server_define.h
 *  @brief define various necessary things for server
 *
 *  @author Chen Chen (chenche1)
 *  @bug no bug known
 */


#ifndef __SERVER_DEFINE_H_
#define __SERVER_DEFINE_H_

#include <netinet/in.h>
#include <netinet/ip.h>
#include "list.h"


/* define various macro */
#define ECHO_PORT 9999
#define BUF_SIZE 4096
#define TIMEOUT_TIME 1    /* in sec */
#define HASH_SIZE    0xff     /* size of hash size of client list */


struct cli_cb{
    struct sockaddr_in cli_addr;
    int cli_fd;
    char buf[BUF_SIZE];
    int buf_ctr;
    struct list_head cli_link;
};

typedef struct cli_cb cli_cb_t;



#endif /* end of __SERVER_DEFINE_H_ */
