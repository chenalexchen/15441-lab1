/** @file server.c
 *  @brief a server based on select
 *
 *
 *  @author Chen Chen (chenche1)
 *  @bug no bug found
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "srv_def.h"
#include "list.h"
#include "srv_log.h"
#include  "err_code.h"
#include "debug_define.h"
#include "http.h"




/* the fds for reading and writing */
static fd_set read_fds, write_fds;
/* the temp fds for reading and writing */
static fd_set read_wait_fds, write_wait_fds;
/* maximal fd */
static int max_fd = 0;
/* socket address */
static struct sockaddr_in sock_addr;
/* the fd for socket */
static int sock_fd = -1;
/* clinet list */
static struct list_head cli_list[HASH_SIZE];


/*
 * define static funtions
 */

/* init global var */
static void init_global_var(void);

/* fd struct handlding */
static int init_fds(fd_set *read, fd_set *write);
static void insert_fd(int fd, fd_set *set);
static void reelect_max_fd(void);


/* for cli_cb handling */
static cli_cb_t *get_cli_cb(int cli_fd);
static int init_cli_cb(cli_cb_t *cli_cb, struct sockaddr_in *addr, int cli_fd);
static void free_cli_cb(cli_cb_t *cli_cb);
static int is_buf_in_empty(cli_cb_t *cli_cb);
static void set_buf_ctr(cli_cb_t *cli_cb, int ctr);



/* for srv function */
static int establish_socket(void);
static int select_wrapper(struct timeval *t);
static int is_new_connection(int fd);
static int create_new_connection(int fd);
static void kill_connections(void);
static int recv_wrapper(int fd);
static int send_wrapper(int fd);
static int process_request(void);






/** helper function to reelect max fd after one of fd is killed */
static void reelect_max_fd(void)
{
    if(!max_fd)
        return;
    int i = max_fd - 1;
    while(!(FD_ISSET(i, &read_fds) ||
            FD_ISSET(i, &write_fds)) &&
          i > 0){i--;}
    max_fd = i + 1;
    dbg_printf("new max fd (%d)", max_fd);
    return;
}


static void init_global_var(void)
{

    int ret = 0, i;
    
    if((ret = init_fds(&read_fds, &write_fds)) < 0){
        err_printf("init_fds failed");
        return;
    }
    
    /* init the hash table */
    for(i = 0; i < HASH_SIZE; i++){
        INIT_LIST_HEAD(&cli_list[i]);
    }

    return;
}


static int init_cli_cb(cli_cb_t *cli_cb, struct sockaddr_in *addr, int cli_fd)
{
    cli_cb->cli_addr = *addr;
    cli_cb->cli_fd = cli_fd;
    memset(cli_cb->buf_in, 0, BUF_IN_SIZE);
    cli_cb->buf_in_pos = 0;
    cli_cb->buf_out = NULL;
    INIT_LIST_HEAD(&cli_cb->req_msg_list);
    /* insert the client cb into hash table */
    list_add_tail(&cli_cb->cli_link, &cli_list[cli_fd % HASH_SIZE]);
    return 0;
}

static void free_cli_cb(cli_cb_t *cli_cb)
{
    if(cli_cb->buf_out)
        free(cli_cb->buf_out);
    
    list_del(&cli_cb->cli_link);
    free(cli_cb);
    return;
}




static int is_buf_in_empty(cli_cb_t *cli_cb)
{
    return *(cli_cb->buf_in) == 0;
}



static void set_buf_ctr(cli_cb_t *cli_cb, int ctr)
{
    cli_cb->buf_in_pos = ctr;
}

static cli_cb_t *get_cli_cb(int cli_fd)
{
    cli_cb_t *item;
    list_for_each_entry(item, &cli_list[cli_fd % HASH_SIZE], cli_link){
        if(item->cli_fd == cli_fd){
            return item;
        }
    }
    return NULL;
}



int close_socket(int sock)
{
    dbg_printf("close conn(%d)", sock);
    if (close(sock))
    {
        fprintf(stderr, "Failed closing socket.\n");
        return 1;
    }
    FD_CLR(sock, &read_fds);
    FD_CLR(sock, &write_fds);
    FD_CLR(sock, &read_wait_fds);
    FD_CLR(sock, &write_wait_fds);
    reelect_max_fd();
    return 0;
}


static int init_fds(fd_set *read, fd_set *write)
{
    int ret = 0;
    FD_ZERO(read); 
    FD_ZERO(write);
    return ret;
}

static void insert_fd(int fd, fd_set *set)
{
    dbg_printf("fd (%d), max_fd(%d)", fd, max_fd);
    if(fd >= max_fd){
        max_fd = fd + 1;
    }
    dbg_printf("fd (%d), max_fd(%d)", fd, max_fd);
    FD_SET(fd, set);
    return;
}

static int establish_socket(void)
{
    int sock;
        
    /* all networked programs must create a socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1){
        err_printf("Failed creating socket.\n");
        return ERR_SOCKET;
    }
    
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(ECHO_PORT);
    sock_addr.sin_addr.s_addr = INADDR_ANY;
    
    /* servers bind sockets to ports---notify the OS they accept connections */
    if (bind(sock, (struct sockaddr *) &sock_addr, sizeof(sock_addr))){
        close_socket(sock);
        fprintf(stderr, "Failed binding socket.\n");
        return ERR_BIND;
    }
    
    if (listen(sock, 5)){
        close_socket(sock);
        fprintf(stderr, "Error listening on socket.\n");
        return ERR_LISTEN;
    }
    return sock;
}

static int select_wrapper(struct timeval *t)
{
    FD_COPY(&read_fds, &read_wait_fds);
    FD_COPY(&write_fds, &write_wait_fds);    
    return select(max_fd, &read_wait_fds, &write_wait_fds, NULL, t);
}

static int is_new_connection(int fd)
{
    return fd == sock_fd && sock_fd != -1;
}

static int create_new_connection(int fd)
{
    socklen_t cli_size;
    struct sockaddr_in cli_addr;
    int cli_sock;
    cli_cb_t *cb;
    int ret;
    cli_size = sizeof(cli_addr);
    if ((cli_sock = accept(fd, (struct sockaddr *) &cli_addr,
                           &cli_size)) == -1) {
        close(fd);
        err_printf("socket accept failure\n");
        return ERR_ACCEPT_FAILURE;
    }
    cb = (cli_cb_t *) malloc(sizeof(cli_cb_t));
    if(cb == NULL){
        
        /* TODO: no more space for additional connection,
         * fix the server by refuse this connection */
        
        return ERR_NO_MEM;
    }
    /* init control block */
    if((ret = init_cli_cb(cb, &cli_addr, cli_sock)) < 0){
        free(cb);
        return ret;
    }
    /* add fd into both read and write fd */
    insert_fd(cli_sock, &read_fds);
    insert_fd(cli_sock, &write_fds);
    return 0;
}

static void kill_connections(void)
{
    int i;
    cli_cb_t *cb, *cb_next;
    /* span the entire cli_list, 1. close existing connection; 2. free
     * existing control block
     */
    for (i = 0; i < HASH_SIZE; i++){
        list_for_each_entry_safe(cb, cb_next, &cli_list[i], cli_link){
            list_del(&cb->cli_link);
            close_socket(cb->cli_fd);
            free(cb);
        }
    }
    return;
}


static int recv_wrapper(int fd)
{
    cli_cb_t *cb;
    int readctr;
    if((cb = get_cli_cb(fd)) !=NULL){
        if(is_buf_in_empty(cb)){
            if((readctr = recv(cb->cli_fd, cb->buf_in, 
                               BUF_IN_SIZE, 0)) 
               > 0){
                dbg_printf("reading socket (%i), readctr(%d)",
                           fd, readctr);
                set_buf_ctr(cb, readctr);
                            /* then do nothing */
            }else{
                /* if no reading is availale, return NULL */
                close_socket(cb->cli_fd);
                free_cli_cb(cb);
                dbg_printf("conn (%i) is closed", fd);
                return 0;
            }
        }else{
            dbg_printf("buf not emptied, socket(%d)",fd);
        }
    }else{
        err_printf("conn (%d) doesn't exist", fd);
        return ERR_CONNECTION_NOT_EXIST;
    }
    return 0;
}

static int send_wrapper(int fd)
{
    cli_cb_t *cb;
    int readctr;

    if((cb = get_cli_cb(fd)) !=NULL){
        
        if(cb->buf_out){

            if((readctr = send(cb->cli_fd, cb->buf_out, 
                               cb->buf_out_ctr, 0))
               != cb->buf_out_ctr){
                close_socket(cb->cli_fd);
                /* free cli_cb */
                free_cli_cb(cb);
                err_printf("Error sending to client.\n");
                return ERR_SEND;
            }else{
                dbg_printf("buf sent, conn (%d), ctr(%d)", fd,
                           cb->buf_out_ctr);
                cb->buf_out = NULL;
            }
        }
    }else{
        err_printf("conn (%d) doesn't exist", fd);
        return ERR_CONNECTION_NOT_EXIST;
    }
    return 0;
}


/* static int fill_rspd_hdr(char *buf_hdr, req_msg_t *req_msg) */
/* { */
    
/* } */

static int handle_head_mthd(req_msg_t *req_msg, cli_cb_t *cb)
{

    return 0;
}


static int handle_get_mthd(req_msg_t *req_msg, cli_cb_t *cb)
{
    int ret;
    /* fill in the header to return to */

    char filename[FILENAME_MAX_LEN];
    char buf_hdr[BUF_HDR_SIZE];
    int ctr = 0; 
    int fd;
    struct stat statbuf;
    char *faddr;
        
    /* copy the default folder */
    strncpy(filename, DEFAULT_FD, FILENAME_MAX_LEN);
    /* try to check whether the req url is / */
    if(!strcmp(req_msg->req_line.url, FS_ROOT)){
        strncat(filename, "index.html", FILENAME_MAX_LEN);
    }else{
        strncat(filename, req_msg->req_line.url, FILENAME_MAX_LEN);
    }

    dbg_printf("filename %s", filename);
    if((fd = open(filename, O_RDONLY)) < 0){
        dbg_printf("file not exist");
        /* return 404 not found */
        snprintf(buf_hdr, BUF_HDR_SIZE, "%s 404 Not Found\r\n\r\n", 
                 req_msg->req_line.ver);        
        if(cb->buf_out)
            free(cb->buf_out);
        if(!(cb->buf_out = (char *)malloc(strlen(buf_hdr)))){
            ret = ERR_NO_MEM;
            goto out1;
        }
        strcpy(cb->buf_out, buf_hdr);
        cb->buf_out_ctr = strlen(buf_hdr);
    }else{
        
        /* resource exist */
        if(fstat(fd, &statbuf) < 0){
            ret = ERR_FSTAT;
            goto out2;
        }
    
        if((faddr = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0)) 
           == MAP_FAILED){
            dbg_printf("mmap failed");
            ret = ERR_MMAP;
            goto out2;
        }
        /* print out response line */
        ctr += snprintf(buf_hdr, BUF_HDR_SIZE, "%s 200 OK\r\n", 
                        req_msg->req_line.ver);
        /* print out header field */
        if(strstr(req_msg->req_line.url, "css")){
            ctr += snprintf(buf_hdr + ctr, BUF_HDR_SIZE - ctr,
                            "Content-Type: text/css\r\n");
        }else if(strstr(req_msg->req_line.url, "png")){
            ctr += snprintf(buf_hdr + ctr, BUF_HDR_SIZE - ctr,
                            "Content-Type: image/png\r\n");
        }else{
            ctr += snprintf(buf_hdr + ctr, BUF_HDR_SIZE - ctr,
                            "Content-Type: text/html\r\n");
        }
        ctr += snprintf(buf_hdr + ctr, BUF_HDR_SIZE - ctr,
                        "Content-Length: %d\r\n", (int)statbuf.st_size);
        ctr += snprintf(buf_hdr + ctr, BUF_HDR_SIZE - ctr,
                        "\r\n");
        
        int buf_hdr_len = strlen(buf_hdr);

        cb->buf_out = (char *)malloc(buf_hdr_len + statbuf.st_size);
        
        if(!cb->buf_out){
            ret = ERR_NO_MEM;
            goto out2;
        }
        
        strncpy(cb->buf_out, buf_hdr, BUF_HDR_SIZE);
        dbg_printf("(but_out): %s", cb->buf_out);
        memcpy(cb->buf_out+buf_hdr_len, faddr, statbuf.st_size);
        
        cb->buf_out_ctr = buf_hdr_len + statbuf.st_size;
        if(munmap(faddr, statbuf.st_size) < 0){
            err_printf("munmap failed");
            ret = ERR_MMAP;
            goto out3;
        }
        close(fd);
    }
    
    return 0;
 out3:
    dbg_printf("premature free buf_out");
    free(cb->buf_out);
 out2:
    if(!fd)
        close(fd);
 out1:
    return ret;
}

static int handle_post_mthd(req_msg_t *req_msg, cli_cb_t *cb)
{
    return 0;
}

static int handle_unknown_mthd(req_msg_t *req_msg, cli_cb_t *cb)
{
    return 0;
}

static int handle_req_msg(cli_cb_t *cb)
{
    req_msg_t *req_msg;
    int ret;
    /* if req msg list is empty */
    if(list_empty(&cb->req_msg_list)){
        //dbg_printf("conn(%d) no req_msg pending", cb->cli_fd);
        return 0;
    }
    /* if req msg list is not empty, try to handle one request */
    req_msg = list_first_entry(&cb->req_msg_list, req_msg_t, req_msg_link);
    list_del(&req_msg->req_msg_link);
    
    
    switch(req_msg->req_line.req){
    case HEAD:
        ret = handle_head_mthd(req_msg, cb);
        break;
    case GET:
        ret = handle_get_mthd(req_msg, cb);
        break;
    case POST:
        ret = handle_post_mthd(req_msg, cb);
        break;
    default:
        ret = handle_unknown_mthd(req_msg, cb);
        break;
    }
    if(ret < 0){
        err_printf("ret = 0x%x", -ret);
        return ret;
    }
    free_req_msg(req_msg);
    free(req_msg);
    return 0;
}


static int process_request(void)
{
    int i;
    int ret = 0;
    cli_cb_t *cb;
    for(i = 0; i < max_fd; i++){
        if(FD_ISSET(i, &read_wait_fds)){
            if(is_new_connection(i)){   /* setup a new connection */
                dbg_printf("set up new connection (%d)", i);
                if((ret = create_new_connection(i)) < 0){
                    return ret;
                }
            }else{                     /* read from this connection */
                if((ret = recv_wrapper(i)) < 0){
                    return ret;
                }
                if((cb = get_cli_cb(i))!=NULL){
                    /*parse the req here */
                    if((ret=parse_cli_cb(cb)) < 0){
                        err_printf("parse failed, conn(%d)",i);
                        return ret;
                    }              
                }  
            } 

        }

        /* check those write wait fds */
        if(FD_ISSET(i, &write_wait_fds)){ /* write to this connection */
            if((cb = get_cli_cb(i))!=NULL){

                if((ret = handle_req_msg(cb)) < 0){
                    err_printf("handle_req_msg failed, err = 0x%x", ret);
                    return ret;
                }
            }
            if((ret = send_wrapper(i)) < 0){
                return ret;
            }
        }
    }
    return 0;
}


int main(int argc, char* argv[])
{
    /* set the select timeout 1s */
    struct timeval time; 
    time.tv_sec = TIMEOUT_TIME;
    time.tv_usec = 0;
    int num;
    int ret = 0;

    /* init global variable */
    init_global_var();

    cprintf("----- Echo Server -----\n");

    /* set up the first socket */    
    if((sock_fd = establish_socket()) < 0){
        err_printf("establish_socket failed\n");
        return sock_fd;
    }   
    insert_fd(sock_fd, &read_fds);    
    dbg_printf("socket established\n");
    

    /* main loop to process the incoming packet */
    while(1){
        while( (num = select_wrapper(&time)) == 0){
            /* if time out */
            cprintf(".");
        }
        if(num < 0){
            /* if select is interrutped by signal, 
             * kill all the outstanding sockets
             * TODO: currently, only one of the sockets is killed
             */
            cprintf("signal received, exit ...");
            /* kill all the exiting connections */
            kill_connections();
            if(close_socket(sock_fd)){ 
                err_printf("close sock_fd failed");
                return EXIT_FAILURE;
            }
            
            return EXIT_SUCCESS;
        }

        if((ret = process_request()) < 0){
            err_printf("error(0x%x) when processing request\n", -ret);
            return EXIT_FAILURE;
        }
    }
    /* should not reach here */ 
    err_printf("should not reach here");
    return EXIT_FAILURE;
}

