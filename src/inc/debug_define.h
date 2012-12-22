/** @file debug_define.h
 *  @brief define some primitives for debuging
 *
 *  @author Chen Chen (chenche1)
 *  @bug no bug report 
 */

#ifndef __DEBUG_DEFINE_H_
#define __DBEUG_DEFINE_H_


#include "stdio.h"

#define DEBUG

#ifdef DEBUG
#define dbg_printf(fmt, args...) do{fprintf(stdout, "(%s)dbg:"fmt"\n",  \
                                            __func__,                   \
                                            ##args); fflush(stdout);}while(0)
#define err_printf(fmt, args...) do{fprintf(stderr, "(%s)err:"fmt"\n", \
                                            __func__,                   \
                                            ##args); fflush(stderr);}while(0)
#else
#define dbg_printf(fmt, args...)
#define err_printf(fmt, args...) 
#endif

/* console printf */
#define cprintf(fmt, args...) do{fprintf(stdout, "^_^:"fmt, ##args);    \
        fflush(stdout);}while(0)


#endif /* end of __DEBUG_DEFINE_H_ */
