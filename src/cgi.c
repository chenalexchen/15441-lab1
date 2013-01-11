/** @file cgi.c
 *  @brief cgi support
 *
 *  @author Chen Chen 
 *  @bug no known bug
 */



#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "srv_def.h"
#include "http.h"
#include "err_code.h"
#include "debug_define.h"


/**************** BEGIN CONSTANTS ***************/
#define FILENAME "../CGI/cgi_dumper.py"
#define BUF_SIZE 4096

/* note: null terminated arrays (null pointer) */
char* ARGV[] = {
                    FILENAME,
                    NULL
               };

char* ENVP[] = {
                    "CONTENT_LENGTH=",
                    "CONTENT-TYPE=",
                    "GATEWAY_INTERFACE=CGI/1.1",
                    "QUERY_STRING=action=opensearch&search=HT&namespace=0&suggest=",
                    "REMOTE_ADDR=128.2.215.22",
                    "REMOTE_HOST=gs9671.sp.cs.cmu.edu",
                    "REQUEST_METHOD=GET",
                    "SCRIPT_NAME=/w/api.php",
                    "HOST_NAME=en.wikipedia.org",
                    "SERVER_PORT=80",
                    "SERVER_PROTOCOL=HTTP/1.1",
                    "SERVER_SOFTWARE=Liso/1.0",
                    "HTTP_ACCEPT=application/json, text/javascript, */*; q=0.01",
                    "HTTP_REFERER=http://en.wikipedia.org/w/index.php?title=Special%3ASearch&search=test+wikipedia+search",
                    "HTTP_ACCEPT_ENCODING=gzip,deflate,sdch",
                    "HTTP_ACCEPT_LANGUAGE=en-US,en;q=0.8",
                    "HTTP_ACCEPT_CHARSET=ISO-8859-1,utf-8;q=0.7,*;q=0.3",
                    "HTTP_COOKIE=clicktracking-session=v7JnLVqLFpy3bs5hVDdg4Man4F096mQmY; mediaWiki.user.bucket%3Aext.articleFeedback-tracking=8%3Aignore; mediaWiki.user.bucket%3Aext.articleFeedback-options=8%3Ashow; mediaWiki.user.bucket:ext.articleFeedback-tracking=8%3Aignore; mediaWiki.user.bucket:ext.articleFeedback-options=8%3Ashow",
                    "HTTP_USER_AGENT=Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.186 Safari/535.1",
                    "HTTP_CONNECTION=keep-alive",
                    "HTTP_HOST=en.wikipedia.org",
                    NULL
               };

char* POST_BODY = "This is the stdin body...\n";
/**************** END CONSTANTS ***************/




void execve_error_handler(void);


static int create_cgi_arg(char ***argv, req_msg_t *req_msg)
{
        *argv = (char **)malloc(sizeof(char *)*2);
        (*argv)[0] = CGI_EXECUTABLE;
        (*argv)[1] = NULL;
        return 0;
}

static char *get_field_value(req_msg_t *req_msg, char *field_name)
{
        msg_hdr_t *msg_hdr;
        list_for_each_entry(msg_hdr, &req_msg->msg_hdr_list, 
                            msg_hdr_link){

                if(!strcmp(msg_hdr->field_name, field_name)){
                        return msg_hdr->field_value;
                }
        }
        return NULL;
}

static int create_cgi_env(char ***envp, req_msg_t *req_msg, 
                          cli_cb_base_t *cgi_parent)
{
        int name_len;
        int value_len;
        int tmp_len;
        int uri_len;
        char *field_value;


        int ret;
        int i = 0;
        int ctr = CGI_ENV_CTR;

        *envp = (char **)malloc(sizeof(char *)*(ctr + 1));

        if(!*envp){
                return ERR_NO_MEM;
        }

        /* for Content-Length */
        if((field_value = get_field_value(req_msg, "Content-Length"))){
                value_len = strlen(field_value);
                err_printf("value_len = %d",value_len);
                name_len = strlen("CONTENT_LENGTH");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "CONTENT_LENGTH", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                err_printf("test");
                name_len = strlen("CONTENT_LENGTH");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "CONTENT_LENGTH", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;
        
        /* for Content-Type */
        if((field_value = get_field_value(req_msg, "Content-Type"))){
                value_len = strlen(field_value);
                name_len = strlen("CONTENT_TYPE");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "CONTENT_TYPE", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                name_len = strlen("CONTENT_TYPE");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "CONTENT_TYPE", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;

        /* for GATEWAY_INTERFACE */
        field_value = "CGI/1.1";
        value_len = strlen(field_value);
        name_len = strlen("GATEWAY_INTERFACE");                
        if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                ret = ERR_NO_MEM;
                return ret;
        }
        memcpy((*envp)[i], "GATEWAY_INTERFACE", name_len);
        (*envp)[i][name_len] = '=';
        memcpy((*envp)[i] + name_len + 1, field_value, value_len);
        (*envp)[i][name_len + 1 + value_len] = 0;

        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;

        /* for PATH_INFO */
        field_value = req_msg->req_line.cgi_url.path_info;
        value_len = strlen(field_value);
        name_len = strlen("PATH_INFO");                
        if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                ret = ERR_NO_MEM;
                return ret;
        }
        memcpy((*envp)[i], "PATH_INFO", name_len);
        (*envp)[i][name_len] = '=';
        memcpy((*envp)[i] + name_len + 1, field_value, value_len);
        (*envp)[i][name_len + 1 + value_len] = 0;
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;

        /* for QUERY_STRING */
        field_value = req_msg->req_line.cgi_url.query_string;
        if(!field_value){
                name_len = strlen("QUERY_STRING");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "QUERY_STRING", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }else{
                value_len = strlen(field_value);
                name_len = strlen("QUERY_STRING");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "QUERY_STRING", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;


        /* for REMOTE_ADDR */
        cli_cb_tcp_t *tcp_par = (cli_cb_tcp_t *)cgi_parent;
        
        err_printf("addr:%s", inet_ntoa(tcp_par->cli_addr.sin_addr));

        field_value = (char *)malloc(CGI_REMOTE_ADDR_LEN + 1);
        if(!field_value){
                ret = ERR_NO_MEM;
                return ret;
        }

        snprintf(field_value, CGI_REMOTE_ADDR_LEN, "%s", 
                 inet_ntoa(tcp_par->cli_addr.sin_addr));
        err_printf("%s", field_value);
        value_len = strlen(field_value);
        name_len = strlen("REMOTE_ADDR");                
        if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                ret = ERR_NO_MEM;
                return ret;
        }
        memcpy((*envp)[i], "REMOTE_ADDR", name_len);
        (*envp)[i][name_len] = '=';
        memcpy((*envp)[i] + name_len + 1, field_value, value_len);
        (*envp)[i][name_len + 1 + value_len] = 0;
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;

        /* REQUEST_METHOD */
        switch(req_msg->req_line.req){
        case GET:
                field_value = "GET";
                break;
        case POST:
                field_value = "POST";
                break;
        case HEAD:
                field_value = "HEAD";
                break;
        default:
                field_value = "GET";
                break;
        }
        value_len = strlen(field_value);
        name_len = strlen("REQUEST_METHOD");                
        if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                ret = ERR_NO_MEM;
                return ret;
        }
        memcpy((*envp)[i], "REQUEST_METHOD", name_len);
        (*envp)[i][name_len] = '=';
        memcpy((*envp)[i] + name_len + 1, field_value, value_len);
        (*envp)[i][name_len + 1 + value_len] = 0;
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;

        /* REQUEST_URI */
        tmp_len = strlen("/cgi");
        uri_len = strlen(req_msg->req_line.cgi_url.path_info);

        field_value = (char *)malloc(tmp_len + uri_len + 1);
        memcpy(field_value, "/cgi", tmp_len);
        memcpy(field_value + tmp_len, req_msg->req_line.cgi_url.path_info,
               uri_len);
        field_value[tmp_len + uri_len] = 0;        
        value_len = strlen(field_value);
        name_len = strlen("REQUEST_URI");                
        if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                ret = ERR_NO_MEM;
                return ret;
        }
        memcpy((*envp)[i], "REQUEST_URI", name_len);
        (*envp)[i][name_len] = '=';
        memcpy((*envp)[i] + name_len + 1, field_value, value_len);
        (*envp)[i][name_len + 1 + value_len] = 0;
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;

        /* SCRIPT_NAME */
        field_value = "/cgi/";
        value_len = strlen(field_value);
        name_len = strlen("SCRIPT_NAME");                
        if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                ret = ERR_NO_MEM;
                return ret;
        }
        memcpy((*envp)[i], "SCRIPT_NAME", name_len);
        (*envp)[i][name_len] = '=';
        memcpy((*envp)[i] + name_len + 1, field_value, value_len);
        (*envp)[i][name_len + 1 + value_len] = 0;
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;

        /* SERVER_PORT */
        if((field_value = (char *)malloc(CGI_REMOTE_ADDR_LEN))){
                sprintf(field_value, "%d", 9999);                
        }
        value_len = strlen(field_value);
        name_len = strlen("SERVER_PORT");                
        if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                ret = ERR_NO_MEM;
                return ret;
        }
        memcpy((*envp)[i], "SERVER_PORT", name_len);
        (*envp)[i][name_len] = '=';
        memcpy((*envp)[i] + name_len + 1, field_value, value_len);
        (*envp)[i][name_len + 1 + value_len] = 0;
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;
        
        /* SERVER_PROTOCOL */
        field_value = "HTTP/1.1";
        value_len = strlen(field_value);
        name_len = strlen("SERVER_PROTOCOL");                
        if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                ret = ERR_NO_MEM;
                return ret;
        }
        memcpy((*envp)[i], "SERVER_PROTOCOL", name_len);
        (*envp)[i][name_len] = '=';
        memcpy((*envp)[i] + name_len + 1, field_value, value_len);
        (*envp)[i][name_len + 1 + value_len] = 0;
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;
        
        /* SERVER_SOFTWARE */
        field_value = "Liso/1.0";
        value_len = strlen(field_value);
        name_len = strlen("SERVER_SOFTWARE");                
        if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                ret = ERR_NO_MEM;
                return ret;
        }
        memcpy((*envp)[i], "SERVER_SOFTWARE", name_len);
        (*envp)[i][name_len] = '=';
        memcpy((*envp)[i] + name_len + 1, field_value, value_len);
        (*envp)[i][name_len + 1 + value_len] = 0;
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;


        /* for Accept */
        if((field_value = get_field_value(req_msg, "Accept"))){
                value_len = strlen(field_value);
                name_len = strlen("HTTP_ACCEPT");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_ACCEPT", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                name_len = strlen("HTTP_ACCEPT");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_ACCEPT", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;


        /* for Referer */
        if((field_value = get_field_value(req_msg, "Referer"))){
                value_len = strlen(field_value);
                name_len = strlen("HTTP_REFERER");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_REFERER", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                name_len = strlen("HTTP_REFERER");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_REFERER", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;


        /* for Accept-Encoding */
        if((field_value = get_field_value(req_msg, "Accept-Encoding"))){
                value_len = strlen(field_value);
                name_len = strlen("HTTP_ACCEPT_ENCODING");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_ACCEPT_ENCODING", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                name_len = strlen("HTTP_ACCEPT_ENCODING");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_ACCEPT_ENCODING", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;


        /* for Accept-Language */
        if((field_value = get_field_value(req_msg, "Accept-Language"))){
                value_len = strlen(field_value);
                name_len = strlen("HTTP_ACCEPT_LANGUAGE");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_ACCEPT_LANGUAGE", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                name_len = strlen("HTTP_ACCEPT_LANGUAGE");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_ACCEPT_LANGUAGE", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;

        /* Accept-Charset */
        if((field_value = get_field_value(req_msg, "Accept-Charset"))){
                value_len = strlen(field_value);
                name_len = strlen("HTTP_ACCEPT_CHARSET");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_ACCEPT_CHARSET", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                name_len = strlen("HTTP_ACCEPT_CHARSET");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_ACCEPT_CHARSET", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;


        /* Host */
        if((field_value = get_field_value(req_msg, "Host"))){
                value_len = strlen(field_value);
                name_len = strlen("HTTP_HOST");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_HOST", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                name_len = strlen("HTTP_HOST");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_HOST", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;


        /* Cookie */
        if((field_value = get_field_value(req_msg, "Cookie"))){
                value_len = strlen(field_value);
                name_len = strlen("HTTP_COOKIE");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_COOKIE", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                name_len = strlen("HTTP_COOKIE");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_COOKIE", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;


        /* User-Agent */
        if((field_value = get_field_value(req_msg, "User-Agent"))){
                value_len = strlen(field_value);
                name_len = strlen("HTTP_USER_AGENT");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_USER_AGENT", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                name_len = strlen("HTTP_USER_AGENT");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_USER_AGENT", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;


        /* Connection */
        if((field_value = get_field_value(req_msg, "Connection"))){
                value_len = strlen(field_value);
                name_len = strlen("HTTP_CONNECTION");                
                if(!((*envp)[i] = (char *)malloc(value_len + name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_CONNECTION", name_len);
                (*envp)[i][name_len] = '=';
                memcpy((*envp)[i] + name_len + 1, field_value, value_len);
                (*envp)[i][name_len + 1 + value_len] = 0;
        }else{
                name_len = strlen("HTTP_CONNECTION");                
                if(!((*envp)[i] = (char *)malloc(name_len + 2))){
                        ret = ERR_NO_MEM;
                        return ret;
                }
                memcpy((*envp)[i], "HTTP_CONNECTION", name_len);
                (*envp)[i][name_len] = '=';
                (*envp)[i][name_len + 1] = 0;
        }
        err_printf("envp(%d):(%s)", i, (*envp)[i]);
        i++;

        (*envp)[i] = NULL;

        return 0;
}

int handle_cgi(req_msg_t *req_msg, cli_cb_base_t *cb)
{
        pid_t pid;

        int stdin_pipe[2] = {-1, -1};
        int stdout_pipe[2] = {-1, -1};

        char **argv;
        char **envp;
        
        cli_cb_cgi_t *cgi_cb;

        int ret;
        if((ret = parse_cgi_url(req_msg)) < 0){
                err_printf("parse cgi url failed, ret = 0x%x", -ret);
                goto out1;
        }


        /*************** BEGIN PIPE **************/
        /* 0 can be read from, 1 can be written to */
        if (pipe(stdin_pipe) < 0){

                err_printf("Error piping for stdin");
                ret = ERR_PIPE;
                goto out1;
        }

        if (pipe(stdout_pipe) < 0){
    
                err_printf("Error piping for stdout");
                ret =  ERR_PIPE;
                goto out2;
        }
        /*************** END PIPE **************/
        
        /*************** BEGIN FORK **************/
        pid = fork();
        /* not good */
        if (pid < 0){
                err_printf("Something really bad happened when fork()ing.");
                return ERR_FORK;
        }
        /* child, setup environment, execve */
        if (pid == 0){
                
                /*************** BEGIN EXECVE ****************/
                close(stdout_pipe[0]);
                stdout_pipe[0] = -1;
                close(stdin_pipe[1]);
                stdin_pipe[1] = -1;
                
                dup2(stdout_pipe[1], fileno(stdout));
                dup2(stdin_pipe[0], fileno(stdin));

                /* you should probably do something with stderr */
                
                               
                /* set up argv and envp */
                err_printf("create cgi arg");
                if((ret = create_cgi_arg(&argv, req_msg)) < 0){
                        err_printf("create cgi arg failed, ret = 0x%x", -ret);
                        exit(-1);
                }

                err_printf("create cgi_env");
                if((ret = create_cgi_env(&envp, req_msg, 
                                         cb)) < 0){
                        err_printf("create cgi env failed, ret = 0x%x", -ret);
                        exit(-1);
                }
                /* pretty much no matter what, 
                 * if it returns bad things happened... */
                if (execve(CGI_EXECUTABLE, argv, envp)){        
                        execve_error_handler();
                        err_printf("Error executing execve syscall");
                        return ERR_EXEC;
                }                
        }

        if (pid > 0){

                close(stdout_pipe[1]);
                stdout_pipe[1] = -1;
                close(stdin_pipe[0]);
                stdin_pipe[0] = -1;
                
                cgi_cb = (cli_cb_cgi_t *)malloc(sizeof(cli_cb_cgi_t));
                if(!cgi_cb){
                        ret = ERR_NO_MEM;
                        goto out3;
                }
                dbg_printf("read fd(%d), write fd(%d)", stdout_pipe[0],
                           stdin_pipe[1]);
                cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;
                dbg_printf("addr_par: %s", 
                           inet_ntoa(tcp_cb->cli_addr.sin_addr));
                dbg_printf("%s",tcp_cb->curr_req_msg->msg_body);
                if((ret = init_cli_cb(&(cgi_cb->base), cb, NULL, stdout_pipe[0],
                                      stdin_pipe[1], CGI)) < 0){
                        ret = ERR_INIT_CLI;
                        goto out4;                        
                }                
                
        }

        return 0;        
 out4:
        free(cgi_cb);    
 out3:
        if(stdout_pipe[0] != -1){
                close(stdout_pipe[0]);
        }
        if(stdout_pipe[1] != -1){
                close(stdout_pipe[1]);
        }
 out2:
        if(stdin_pipe[0] != -1){
                close(stdin_pipe[0]);
        }
        if(stdin_pipe[1] != -1){
                close(stdin_pipe[1]);
        }
 out1:
        return ret;
}






/**************** BEGIN UTILITY FUNCTIONS ***************/
/* error messages stolen from: http://linux.die.net/man/2/execve */
void execve_error_handler()
{
    switch (errno)
    {
        case E2BIG:
            fprintf(stderr, "The total number of bytes in the environment \
(envp) and argument list (argv) is too large.\n");
            return;
        case EACCES:
            fprintf(stderr, "Execute permission is denied for the file or a \
script or ELF interpreter.\n");
            return;
        case EFAULT:
            fprintf(stderr, "filename points outside your accessible address \
space.\n");
            return;
        case EINVAL:
            fprintf(stderr, "An ELF executable had more than one PT_INTERP \
segment (i.e., tried to name more than one \
interpreter).\n");
            return;
        case EIO:
            fprintf(stderr, "An I/O error occurred.\n");
            return;
        case EISDIR:
            fprintf(stderr, "An ELF interpreter was a directory.\n");
            return;
        case ELIBBAD:
            fprintf(stderr, "An ELF interpreter was not in a recognised \
format.\n");
            return;
        case ELOOP:
            fprintf(stderr, "Too many symbolic links were encountered in \
resolving filename or the name of a script \
or ELF interpreter.\n");
            return;
        case EMFILE:
            fprintf(stderr, "The process has the maximum number of files \
open.\n");
            return;
        case ENAMETOOLONG:
            fprintf(stderr, "filename is too long.\n");
            return;
        case ENFILE:
            fprintf(stderr, "The system limit on the total number of open \
files has been reached.\n");
            return;
        case ENOENT:
            fprintf(stderr, "The file filename or a script or ELF interpreter \
does not exist, or a shared library needed for \
file or interpreter cannot be found.\n");
            return;
        case ENOEXEC:
            fprintf(stderr, "An executable is not in a recognised format, is \
for the wrong architecture, or has some other \
format error that means it cannot be \
executed.\n");
            return;
        case ENOMEM:
            fprintf(stderr, "Insufficient kernel memory was available.\n");
            return;
        case ENOTDIR:
            fprintf(stderr, "A component of the path prefix of filename or a \
script or ELF interpreter is not a directory.\n");
            return;
        case EPERM:
            fprintf(stderr, "The file system is mounted nosuid, the user is \
not the superuser, and the file has an SUID or \
SGID bit set.\n");
            return;
        case ETXTBSY:
            fprintf(stderr, "Executable was open for writing by one or more \
processes.\n");
            return;
        default:
            fprintf(stderr, "Unkown error occurred with execve().\n");
            return;
    }
}
/**************** END UTILITY FUNCTIONS ***************/


