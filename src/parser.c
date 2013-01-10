/** @file parser.c
 *  @brief define a simple parser for handling the request 
 *
 *  @author Chen Chen
 *  @bug no known bugs
 */

#include <strings.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "list.h"
#include "http.h"
#include "debug_define.h"
#include "srv_def.h"
#include "err_code.h"


void *strncpy_alloc(char *str, int len)
{
    char *s = (char *)malloc(len + 1);
    if(!s)
        return NULL;
    s = memcpy(s, str, len);
    *(s+len) = 0;
    return s;
}



static void shift_req_msg(cli_cb_tcp_t *cb)
{

        char *buf = cb->buf_proc;
        cb->buf_proc_ctr -= (cb->par_msg_end - cb->buf_proc);
        while(*(cb->par_msg_end)){ 
                *(buf++) = *(cb->par_msg_end++); 
        } 
        *(buf) = 0;
        return;
}

static int parse_req_line(cli_cb_tcp_t *cb, req_msg_t *req_msg)
{
    int ret;


    cb->par_pos = cb->buf_proc;
    /* skip "annoying" char at the beginning of req msg */
    cb->par_pos += strspn(cb->par_pos, " \r\n");
    char *tmp_str;
    if((cb->par_next = strchr(cb->par_pos, ' '))!=NULL){
        tmp_str = strncpy_alloc(cb->par_pos, cb->par_next - cb->par_pos);
        if(!tmp_str){
            /* TODO: err */
            err_printf("no mem");
            ret = ERR_NO_MEM;
            goto out1;
        }
        dbg_printf("mthd(%s)",tmp_str);
        if(!strcmp(tmp_str, "GET")){
            req_msg->req_line.req = GET;            
        }else if(!strcmp(tmp_str, "OPTIONS")){
            req_msg->req_line.req = OPTIONS;
        }else if(!strcmp(tmp_str, "HEAD")){
            req_msg->req_line.req = HEAD;
        }else if(!strcmp(tmp_str, "POST")){
            req_msg->req_line.req = POST;
        }else if(!strcmp(tmp_str, "PUT")){
            req_msg->req_line.req = PUT;
        }else if(!strcmp(tmp_str, "DELETE")){
            req_msg->req_line.req = DELETE;
        }else if(!strcmp(tmp_str, "TRACE")){
            req_msg->req_line.req = TRACE;
        }else if(!strcmp(tmp_str, "CONNECT")){
            req_msg->req_line.req = CONNECT;
        }else{
            req_msg->req_line.req = EXT;
        }
    }
    cb->par_pos = cb->par_next + 1;

    if((cb->par_next = strchr(cb->par_pos, ' '))!= NULL){
        req_msg->req_line.url = (char *)strncpy_alloc(cb->par_pos, 
                                                     cb->par_next 
                                                     - cb->par_pos);
        if(!req_msg->req_line.url){

            ret = ERR_NO_MEM;
            goto out2;
        }
        dbg_printf("%s", req_msg->req_line.url);        
    }else{

        ret = ERR_PARSE_MALFORMAT_REQ_MSG;
        goto out2;
    }
    cb->par_pos = cb->par_next + 1;
    
    if((cb->par_next = strstr(cb->par_pos, LINE_END_STR))!=NULL){
        req_msg->req_line.ver = (char *)strncpy_alloc(cb->par_pos, 
                                                     cb->par_next - 
                                                     cb->par_pos);
        if(!req_msg->req_line.ver){

            ret = ERR_NO_MEM;
            goto out3;
        }
        dbg_printf("%s", req_msg->req_line.ver);
    }else{

        ret = ERR_PARSE_MALFORMAT_REQ_MSG;
        goto out3;
    }
    cb->par_pos = cb->par_next + sizeof(LINE_END_STR)-1;
    free(tmp_str);
    return 0;


 out3:
    free(req_msg->req_line.url);
 out2:
    free(tmp_str);
 out1:
    return ret;
}

static int parse_msg_hdr_semantic(msg_hdr_t *msg_hdr, req_msg_t *req_msg)
{
    if(!strcmp(msg_hdr->field_name, "Content-Length")){
        sscanf(msg_hdr->field_value, "%d", &req_msg->msg_body_len);
        dbg_printf("msg_hdr_len %d", req_msg->msg_body_len);
    }
    return 0;
}

int parse_msg_hdr(cli_cb_tcp_t *cb, req_msg_t *req_msg)
{
    int ret;

    msg_hdr_t *msg_hdr = (msg_hdr_t *)malloc(sizeof(msg_hdr_t));
    if(!msg_hdr){
        ret = ERR_NO_MEM;
        goto out1;
    }
    if(!(cb->par_next = strchr(cb->par_pos, ':'))){
        /* parse err */
        ret =  ERR_PARSE_MALFORMAT_REQ_MSG;
        goto out2;
    }
    if(!(msg_hdr->field_name = strncpy_alloc(cb->par_pos, 
                                      cb->par_next - cb->par_pos))){
        ret = ERR_NO_MEM;
        goto out2;
    }
    cb->par_pos = cb->par_next + 1;
    
    /* first span over the space ahead */
    cb->par_pos += strspn(cb->par_pos, " ");
    
    /* parse the field value */
    if(!(cb->par_next = strstr(cb->par_pos, LINE_END_STR))){

        ret = ERR_PARSE_MALFORMAT_REQ_MSG;
        goto out3;
    }

    if(!(msg_hdr->field_value = strncpy_alloc(cb->par_pos,
                                           cb->par_next - cb->par_pos))){

        ret = ERR_NO_MEM;
        goto out3;
    }
    
    cb->par_pos = cb->par_next + sizeof(LINE_END_STR)-1;
    
    if((ret = parse_msg_hdr_semantic(msg_hdr, req_msg)) < 0){
        err_printf("parse_msg_hdr_semantic failed, ret = 0x%x", -ret);
        goto out4;
    }
    /* add msg_hdr into req */
    insert_msg_hdr(msg_hdr, req_msg);
    dbg_printf("msg_hdr field_name: (%s) \t field_value: (%s)", 
               msg_hdr->field_name, msg_hdr->field_value);
    
    /* parse msg hdr semantically */
    
    return 0;
 out4:
    free(msg_hdr->field_value);
 out3:
    free(msg_hdr->field_name);
 out2:
    free(msg_hdr);
 out1:
    return ret;
}


static int is_parse_end(cli_cb_tcp_t *cb)
{
    dbg_printf("par_pos 0x%0llx, par_msg_end 0x%0llx", 
               (unsigned long long)cb->par_pos,
               (unsigned long long)cb->par_msg_end);    
    int ret = cb->par_pos + sizeof(REQ_END_STR) - sizeof(LINE_END_STR) 
        >= cb->par_msg_end;
    if(ret){
        cb->par_pos = cb->par_msg_end;
        
    }
    return ret;
}


void insert_req_msg(req_msg_t *msg, cli_cb_tcp_t *cb)
{
    list_add_tail(&msg->req_msg_link, &cb->req_msg_list);
    return;
}

static int parse_msg_body(cli_cb_tcp_t *cb, req_msg_t *msg)
{
    if(msg->req_line.req == POST && msg->msg_body_len != 0){
        /* parse the msg body */
        cb->par_pos = cb->par_msg_end;
        msg->msg_body = strncpy_alloc(cb->par_pos, msg->msg_body_len);
        if(!msg->msg_body){
            err_printf("NO MEM");
            return ERR_NO_MEM;
        }
    }
    return 0;
}

/* function must be invoked when req_msg is re-initialized */
int parse_req_msg(cli_cb_tcp_t *cb)
{
    int ret;
    req_msg_t *req_msg;
    while(1){

        /* first check whether an entire req msg is in buf_proc */
        cb->par_msg_end = strstr(cb->buf_proc, REQ_END_STR);
        dbg_printf("par_msg_end = 0x%llx", 
                   (unsigned long long)cb->par_msg_end);
        if(!cb->par_msg_end){
            dbg_printf("no entire req msg in buf_proc");
            break;
        }
        cb->par_msg_end += sizeof(REQ_END_STR) - 1;
        
        req_msg = (req_msg_t *)malloc(sizeof(req_msg_t));

        if(!req_msg){
            ret = ERR_NO_MEM;
            goto out1;
        }
        /* init the req msg */
        init_req_msg(req_msg);
        
        /* parse the first line of the req */
        if((ret = parse_req_line(cb,req_msg)) < 0){
            /* parse req line err */
            dbg_printf("parse_req_line err");
            goto out2;
        }
        while(!is_parse_end(cb)){
            if((ret = parse_msg_hdr(cb,req_msg)) < 0){
                err_printf("parse_msg_hdr failed");
                goto out2;
            }
            
        }
        if((ret = parse_msg_body(cb, req_msg)) < 0){
            err_printf("parse_msg_body failed");
            goto out2;
        }
        insert_req_msg(req_msg, cb);
        dbg_printf("parse_req_msg finished");
        shift_req_msg(cb);
    }
    return 0;
 out2:
    free(req_msg);
 out1:
    return ret;
}

static int shift_buf_in(cli_cb_tcp_t *cb)
{

    /* copy buf_in to buf_proc */
    if(cb->buf_in_ctr + cb->buf_proc_ctr > BUF_PROC_SIZE){
        /* TODO:buf_proc will be overflowed, truncate the req and process */
        err_printf("buf_proc overflowed");
        return ERR_PARSE_REQ_MSG_TOO_LONG;
    }
    strncat(cb->buf_proc, cb->buf_in, BUF_IN_SIZE);
    cb->buf_proc_ctr += cb->buf_in_ctr;
    /* clear the buf in */
    make_buf_empty(cb->buf_in, &cb->buf_in_ctr);
    
    return 0;
}

int parse_generic(cli_cb_base_t *cb)
{
    int ret;
    cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;

    if((ret = shift_buf_in(tcp_cb)) < 0){
        return ret;
    }

    if((ret = parse_req_msg(tcp_cb)) < 0){
        err_printf("parse_req_msg failed");
        return ret;
    }
    return 0;
}


int parse_cgi_url(req_msg_t *msg)
{
        char *cgi_url = msg->req_line.url;
        char *curr_pos = NULL;
        char *next_pos = NULL;
        char *end_pos = NULL;

        int ret = 0;
        curr_pos = strstr(cgi_url, CGI_PREFIX);
        if(curr_pos != cgi_url){
                err_printf("cgi url(%s) not correct", msg->req_line.url);
                ret = ERR_CGI_PARSE;
                goto out1;
        }
        curr_pos += (sizeof(CGI_PREFIX) - 1);
        /* preserve the first '/' */
        curr_pos -= 1;
        
        /* end_pos pointed at the null terminator */
        end_pos = cgi_url + strlen(cgi_url);

        if(!(next_pos = strchr(curr_pos, '?'))){
                /* TODO: does this mean that current cgi doesn't have 
                 * parameter?
                 */
                err_printf("? doesn't exist");
                ret = ERR_PARSE_MALFORMAT_REQ_MSG;
                goto out1;
        }
        
        if(!(msg->req_line.cgi_url.path_info = 
             (char *)strncpy_alloc(curr_pos, 
                                   next_pos - curr_pos))){
                ret = ERR_NO_MEM;
                goto out1;
        }
        dbg_printf("path_info: %s", msg->req_line.cgi_url.path_info);
        /* skip '?' */
        curr_pos = next_pos + 1;
        if(!(msg->req_line.cgi_url.query_string = 
             (char *)strncpy_alloc(curr_pos,
                                   end_pos - curr_pos))){
                ret = ERR_NO_MEM;
                goto out2;
        }
        dbg_printf("query_string: %s", msg->req_line.cgi_url.query_string);
        return 0;
 out2:
        free(msg->req_line.cgi_url.path_info);
        msg->req_line.cgi_url.path_info = NULL;
 out1:        
        return ret;
}


void init_req_msg(req_msg_t *msg)
{

    msg->req_line.ver = NULL;
    msg->req_line.url = NULL;
    init_cgi_url(&msg->req_line.cgi_url);

    msg->msg_body = NULL;
    msg->msg_body_len = 0;
    msg->msg_hdr_ctr = 0;
    INIT_LIST_HEAD(&msg->msg_hdr_list);
}


void init_msg_hdr(msg_hdr_t *hdr)
{
    hdr->field_name = NULL;
    hdr->field_value = NULL;
    return;
}

void insert_msg_hdr(msg_hdr_t *hdr, req_msg_t *msg)
{
    list_add_tail(&hdr->msg_hdr_link, &msg->msg_hdr_list);
    msg->msg_hdr_ctr ++;
    return;
}

static void clear_req_line(req_line_t *req_line)
{
    if(req_line->url){
        free(req_line->url);
        req_line->url = NULL;
    }
    
    if(req_line->ver){
        free(req_line->ver);
        req_line->ver = NULL;
    }
    return;
}

static void clear_msg_hdr(msg_hdr_t *msg_hdr)
{
    if(msg_hdr->field_name){
        free(msg_hdr->field_name);
        msg_hdr->field_name = NULL;
    }

    if(msg_hdr->field_value){
        free(msg_hdr->field_value);
        msg_hdr->field_value = NULL;
    }

    return;
}


void clear_req_msg(req_msg_t *msg)
{
    clear_req_line(&msg->req_line);
    msg_hdr_t *hdr, *hdr_next;
    list_for_each_entry_safe(hdr, hdr_next, &msg->msg_hdr_list,
                            msg_hdr_link){
        list_del(&hdr->msg_hdr_link);
        clear_msg_hdr(hdr);
        free(hdr);
    }
    if(msg->msg_body)
        free(msg->msg_body);

}



int init_cgi_url(cgi_url_t *url)
{
        url->path_info = NULL;
        url->query_string = NULL;
        return 0;
}


void clear_cgi_url(cgi_url_t *url)
{
        if(url->path_info)
                free(url->path_info);
        if(url->query_string)
                free(url->query_string);
        return;
}
