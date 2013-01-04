/** @file log.c
 *  @brief log facility of the server
 *  
 *  @author Chen Chen
 *  @bug no bug known
 */

#include "stdio.h"
#include "inc/srv_log.h"
#include "inc/err_code.h"

/* define globally used fd for server log */
int srv_log_fd;


int srv_log_init(void)
{
    srv_log_fd = fopen(SRV_LOG_FILENAME, "rw");
    if(srv_log_fd == NULL){
        return ERR_LOG_FILE;
    }
}

