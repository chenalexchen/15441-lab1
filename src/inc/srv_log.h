/** @file srv_log.h
 *  @brief define various functions for logging in server
 *
 *   TODO: add time stamp for the log
 *
 *  @author Chen Chen (chenche1)
 *  @bug no known bug
 */


#ifndef __SRV_LOG_H_
#define __SRV_LOG_H_


#include "stdio.h"


/* srv_log_fd is defined in log.c */
extern int srv_log_fd;


#define DEBUG
#ifdef DEBUG
#define logprintf(fmt, args...) do{fprintf(stdout, "^_^:"fmt, ##args);    \
        fflush(stdout);}while(0)
#else
#define logprintf(fmt, args...) do{fprintf(srv_log_fd, "^_^:"fmt, ##args);    \
        fflush(srv_log_fd);}while(0)
#endif

/* console printf */
#define cprintf(fmt, args...) do{fprintf(stdout, "^_^:"fmt, ##args);    \
        fflush(stdout);}while(0)


#define SRV_LOG_FILENAME  "liso_log.h"

void srv_log_init(void);







#endif /* end of __SRV_LOG_H_ */ 
