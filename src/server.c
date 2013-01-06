/** @file server.c
 *  @brief a server based on select
 *
 *  
 *  We would rather use memcpy than strcpy(strncpy) to avoid uncontrollable 
 *  copy behavior
 *
 *  TODO: add sigchld handler to handle cgi child exit asynchoronously
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

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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
static struct list_head cli_read_list[HASH_SIZE];
static struct list_head cli_write_list[HASH_SIZE];

/* for cert and private key files */
static int tcp_port = TCP_PORT;
static int ssl_port = SSL_PORT;

static char *srv_cert_file = "pki_jungle/myCA/certs/server.crt";
static char *srv_private_key_file = "pki_jungle/myCA/private/server.key";
//static char *ca_cert_file = "pki_jungle/myCA/certs/myca.crt";
//static char *ca_private_key_file = "pki_jungle/myCA/private/myca.key";

SSL_CTX *ssl_ctx;
const SSL_METHOD *ssl_mthd;



/*
 * define static funtions
 */

/* init global var */
static void init_global_var(void);

/* fd struct handlding */
static int init_fds(fd_set *read, fd_set *write);
static void insert_fd(int fd, fd_set *set);
static void reelect_max_fd(void);


static int is_buf_in_empty(cli_cb_t *cli_cb);
static void set_buf_ctr(cli_cb_t *cli_cb, int ctr);


/* for tcp cli_cb_mthd_t */
static int tcp_new_connection(cli_cb_t *cb);
static int tcp_recv_wrapper(cli_cb_t *cb);
static int tcp_send_wrapper(cli_cb_t *cb);
static int tcp_close_socket(cli_cb_t *cb);
static int handle_req_msg(cli_cb_t *cb);
static int ssl_new_connection(cli_cb_t *cb);
static int ssl_recv_wrapper(cli_cb_t *cb);
static int ssl_send_wrapper(cli_cb_t *cb);
static int ssl_close_socket(cli_cb_t *cb);
static int is_handle_req_msg_pending(cli_cb_t *cb);
static int cgi_recv_wrapper(cli_cb_t *cb);
static int cgi_send_wrapper(cli_cb_t *cb);
static int cgi_close_socket(cli_cb_t *cb);


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

static void init_ssl_var(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    ssl_mthd = SSLv3_method();
    ssl_ctx = SSL_CTX_new(ssl_mthd);
    if(!ssl_ctx){
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    /* load certificate file and private key file */
    if(SSL_CTX_use_certificate_file(ssl_ctx, srv_cert_file, 
                                    SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);

        exit(1);
    }
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx, srv_private_key_file, 
                                   SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);

        exit(1);
    }

    if(!SSL_CTX_check_private_key(ssl_ctx)){
        err_printf("cert and priv key don't match");
        exit(1);
    }
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
        INIT_LIST_HEAD(&cli_read_list[i]);
        INIT_LIST_HEAD(&cli_write_list[i]);
    }


    /* init ssl related var */
    init_ssl_var();
    return;
}


int init_cli_cb(cli_cb_t *cli_cb, struct sockaddr_in *addr, int cli_fd_read,
                int cli_fd_write,
                cli_cb_type_t type, int is_ssl)
{    
    if(addr){
        cli_cb->cli_addr = *addr;
    }
    cli_cb->cli_fd_read = cli_fd_read;
    cli_cb->cli_fd_write = cli_fd_write;
    /* init various buffers */
    memset(cli_cb->buf_in, 0, BUF_IN_SIZE);
    cli_cb->buf_in_ctr = 0;
    memset(cli_cb->buf_proc, 0, BUF_PROC_SIZE);
    cli_cb->buf_proc_ctr = 0;

    /* clear status vars */
    cli_cb->is_handle_req_msg_pending = 0;
    cli_cb->is_handle_cgi_pending = 0;

    /* init mthd */
    cli_cb->type = type;
    cli_cb->is_ssl = is_ssl;

    if(!is_ssl){
        switch(cli_cb->type){
        case LISTEN:
            cli_cb->mthd.new_connection = tcp_new_connection;
            cli_cb->mthd.recv = NULL;
            cli_cb->mthd.send = NULL;
            cli_cb->mthd.close = tcp_close_socket;
            cli_cb->mthd.is_handle_req_msg_pending = NULL;
            cli_cb->mthd.handle_req_msg = handle_req_msg;
            break;
        case CLI:
            cli_cb->mthd.new_connection = NULL;
            cli_cb->mthd.recv = tcp_recv_wrapper;
            cli_cb->mthd.send = tcp_send_wrapper;
            cli_cb->mthd.close = tcp_close_socket;
            cli_cb->mthd.is_handle_req_msg_pending = 
                    is_handle_req_msg_pending;
            cli_cb->mthd.handle_req_msg = handle_req_msg;
            break;
        case CGI:
                cli_cb->mthd.new_connection = NULL;
                cli_cb->mthd.recv = cgi_recv_wrapper;
                cli_cb->mthd.send = cgi_send_wrapper;
                cli_cb->mthd.close = cgi_close_socket;
                cli_cb->mthd.is_handle_req_msg_pending = 
                        is_handle_req_msg_pending;
                cli_cb->mthd.handle_req_msg = NULL;
                break;
        default:
            err_printf("unknown cli type");
            return ERR_UNKNOWN_CLI_TYPE;
        }
    }else{
        switch(cli_cb->type){
        case LISTEN:
            cli_cb->mthd.new_connection = ssl_new_connection;
            cli_cb->mthd.recv = NULL;
            cli_cb->mthd.send = NULL;
            cli_cb->mthd.close = ssl_close_socket;
            cli_cb->mthd.is_handle_req_msg_pending = NULL;
            cli_cb->mthd.handle_req_msg = handle_req_msg;
            break;
        case CLI:
            cli_cb->mthd.new_connection = NULL;
            cli_cb->mthd.recv = ssl_recv_wrapper;
            cli_cb->mthd.send = ssl_send_wrapper;
            cli_cb->mthd.close = ssl_close_socket;
            cli_cb->mthd.is_handle_req_msg_pending = 
                    is_handle_req_msg_pending;
            cli_cb->mthd.handle_req_msg = handle_req_msg;
            break;
        default:
            err_printf("unknown cli type");
            return ERR_UNKNOWN_CLI_TYPE;
        }
    }
    cli_cb->mthd.parse = parse_cli_cb;

    cli_cb->buf_out_ctr = -1;

    INIT_LIST_HEAD(&cli_cb->req_msg_list);
    
    dbg_printf("add new client cb(%d)", 
               cli_cb->cli_fd_read);

    /* insert the fd */
    switch(cli_cb->type){
    case LISTEN:
            insert_fd(cli_fd_read, &read_fds);
            list_add_tail(&cli_cb->cli_rlink, 
                          &cli_read_list[cli_fd_read % HASH_SIZE]);
            break;
    case CGI:
    case CLI:
            insert_fd(cli_fd_read, &read_fds);
            insert_fd(cli_fd_write, &write_fds);
            list_add_tail(&cli_cb->cli_rlink, 
                          &cli_read_list[cli_fd_read % HASH_SIZE]);
            list_add_tail(&cli_cb->cli_wlink, 
                          &cli_write_list[cli_fd_write % HASH_SIZE]);
            break;

    }
    return 0;
}


void free_cli_cb(cli_cb_t *cli_cb)
{
        req_msg_t *msg_curr, *msg_next;
        list_for_each_entry_safe(msg_curr, msg_next,
                                 &cli_cb->req_msg_list,
                                 req_msg_link){
                free(msg_curr);
        }
        dbg_printf("try to free cli_cb(%d)", 
                   cli_cb->cli_fd_read);

        switch(cli_cb->type){
        case LISTEN:
                list_del(&cli_cb->cli_rlink);
                break;
        case CGI:
        case CLI:
                list_del(&cli_cb->cli_rlink);
                list_del(&cli_cb->cli_wlink);
                break;
                
        }

        free(cli_cb);
        return;
}


static int is_handle_req_msg_pending(cli_cb_t *cb)
{
        return cb->is_handle_req_msg_pending;
}


static int is_buf_in_empty(cli_cb_t *cli_cb)
{
        return *(cli_cb->buf_in) == 0;
}



static void set_buf_ctr(cli_cb_t *cli_cb, int ctr)
{
        cli_cb->buf_in_ctr = ctr;
}

cli_cb_t *get_cli_cb(int cli_fd, int rw)
{
        cli_cb_t *item;
        if(!rw){
                list_for_each_entry(item, &cli_read_list[cli_fd % HASH_SIZE], 
                                    cli_rlink){

                        if(item->cli_fd_read == cli_fd){
                                return item;
                        }
                }
                
        }else{
                list_for_each_entry(item, &cli_write_list[cli_fd % HASH_SIZE], 
                                    cli_wlink){
                        
                        if(item->cli_fd_write == cli_fd){
                                return item;
                        }
                }
        }
        return NULL;
}


static int close_socket(int sock)
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

static int tcp_close_socket(cli_cb_t *cb)
{
        int ret;
        
        dbg_printf("close socket(%d)", cb->cli_fd_read);
        if((ret = close_socket(cb->cli_fd_read)) < 0){
                ret = ERR_CLOSE_SOCKET;
                return ret;
        }
        free_cli_cb(cb);
        return 0;
}


static int ssl_close_socket(cli_cb_t *cb)
{
    int ret;
    dbg_printf("close socket (%d)", cb->cli_fd_read);
    if((ret = SSL_shutdown(cb->ssl)) < 0){
        ret = ERR_CLOSE_SSL_SOCKET;
        return ret;
    }
    
    SSL_free(cb->ssl);
    if((ret = close_socket(cb->cli_fd_read)) < 0){
        ret = ERR_CLOSE_SOCKET;
        return ret;
    }
    free_cli_cb(cb);    
    return 0;
}


static int cgi_close_socket(cli_cb_t *cb)
{
        int ret;
        
        dbg_printf("close socket(%d)", cb->cli_fd_read);
        if((ret = close(cb->cli_fd_read)) < 0){
                ret = ERR_CLOSE_FD;
                return ret;
        }
        if((ret = close(cb->cli_fd_write)) < 0){
                ret = ERR_CLOSE_FD;
                return ret;
        }
        cb->cgi_parent->is_handle_req_msg_pending = 0;
        cb->cgi_parent->is_handle_cgi_pending = 0;
        free_cli_cb(cb);
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

int establish_socket(void)
{
    int ret = 0;
    int sock;
    cli_cb_t *cb;
    /* all networked programs must create a socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1){
        err_printf("Failed creating socket.\n");
        return ERR_SOCKET;
    }
    
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(tcp_port);
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


    cb = (cli_cb_t *) malloc(sizeof(cli_cb_t));
    if(cb == NULL){
        return ERR_NO_MEM;
    }
    /* init control block */
    if((ret = init_cli_cb(cb, NULL, sock, sock, LISTEN, 0)) < 0){
        free(cb);
        return ret;
    }

    /* Below, set up the socket for ssl */

    /* all networked programs must create a socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1){
        err_printf("Failed creating socket.\n");
        return ERR_SOCKET;
    }
    
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(ssl_port);
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


    cb = (cli_cb_t *) malloc(sizeof(cli_cb_t));
    if(cb == NULL){
        return ERR_NO_MEM;
    }
    /* init control block */
    if((ret = init_cli_cb(cb, NULL, sock, sock, LISTEN, 1)) < 0){
        free(cb);
        return ret;
    }

    return 0;


}

int select_wrapper(struct timeval *t)
{
        read_wait_fds = read_fds;
        write_wait_fds = write_fds;
        return select(max_fd, &read_wait_fds, &write_wait_fds, NULL, t);
}



static int tcp_new_connection(cli_cb_t *cb)
{
    socklen_t cli_size;
    struct sockaddr_in cli_addr;
    int cli_sock;
    cli_cb_t *cb_new;
    int ret;
    cli_size = sizeof(cli_addr);
    if ((cli_sock = accept(cb->cli_fd_read, (struct sockaddr *) &cli_addr,
                           &cli_size)) == -1) {
        cb->mthd.close(cb);
        err_printf("socket accept failure\n");
        return ERR_ACCEPT_FAILURE;
    }
    cb_new = (cli_cb_t *) malloc(sizeof(cli_cb_t));
    if(cb_new == NULL){
        
        /* TODO: no more space for additional connection,
         * fix the server by refuse this connection */
        
        return ERR_NO_MEM;
    }
    /* init control block */
    if((ret = init_cli_cb(cb_new, &cli_addr, cli_sock, cli_sock, CLI, 0)) < 0){
        free(cb_new);
        return ret;
    }

    dbg_printf("conn(%d) create conn(%d)", cb->cli_fd_read, 
               cb_new->cli_fd_read);
    return 0;
}

static int ssl_new_connection(cli_cb_t *cb)
{
    socklen_t cli_size;
    struct sockaddr_in cli_addr;
    int cli_sock;
    cli_cb_t *cb_new;
    int ret;

    cli_size = sizeof(cli_addr);
    dbg_printf("accept fd(%d)", cb->cli_fd_read);
    if ((cli_sock = accept(cb->cli_fd_read, (struct sockaddr *) &cli_addr,
                           &cli_size)) == -1) {
        cb->mthd.close(cb);
        err_printf("socket accept failure\n");
        free(cb);
        return ERR_ACCEPT_FAILURE;
    }
    cb_new = (cli_cb_t *) malloc(sizeof(cli_cb_t));
    if(cb_new == NULL){
        return ERR_NO_MEM;
    }

    /* init control block */
    if((ret = init_cli_cb(cb_new, &cli_addr, cli_sock, cli_sock, CLI, 1)) < 0){
        free(cb_new);
        return ret;
    }

    if(!(cb_new->ssl = SSL_new(ssl_ctx))){
        return ERR_SSL_NEW;
    }
    dbg_printf("SSL_new succeed");
    SSL_set_fd(cb_new->ssl, cb_new->cli_fd_read);
    dbg_printf("set fd(%d) succeed", cb_new->cli_fd_read);
    if((ret = SSL_accept(cb_new->ssl)) < 0){
        ERR_print_errors_fp(stderr);
        return ERR_SSL_ACCEPT;
    }

    dbg_printf("SSL connection using %s\n", SSL_get_cipher(cb_new->ssl));


    dbg_printf("conn(%d) create conn(%d)", cb->cli_fd_read, 
               cb_new->cli_fd_read);
    return 0;
}

int tcp_recv_wrapper(cli_cb_t *cb)
{
        int readctr;
        if(is_buf_in_empty(cb)){
                if((readctr = recv(cb->cli_fd_read, cb->buf_in, 
                                   BUF_IN_SIZE, 0)) 
                   > 0){
                        dbg_printf("reading socket (%i), readctr(%d)",
                                   cb->cli_fd_read, readctr);
                        /* add null terminator to cb->buf_in */
                        *(cb->buf_in + readctr) = 0;
                        set_buf_ctr(cb, readctr);
                        /* then do nothing */
                }else{
                    /* if no reading is availale, return NULL */
                        cb->mthd.close(cb);
                        dbg_printf("conn (%i) is closed", cb->cli_fd_read);
                        
                        return 0;
                }
        }else{
                dbg_printf("buf not emptied, socket(%d)",cb->cli_fd_read);
                return ERR_BUF;
        }
        return 0;
}



int ssl_recv_wrapper(cli_cb_t *cb)
{
        int readctr;
        if(is_buf_in_empty(cb)){
                if((readctr = SSL_read(cb->ssl, cb->buf_in, 
                                       BUF_IN_SIZE)) 
                   > 0){
                        dbg_printf("reading socket (%i), readctr(%d)",
                                   cb->cli_fd_read, readctr);
                        /* add null terminator to cb->buf_in */
                        *(cb->buf_in + readctr) = 0;
                        set_buf_ctr(cb, readctr);
                        /* then do nothing */
                }else{
                        /* if no reading is availale, return NULL */
                        cb->mthd.close(cb);
                        dbg_printf("conn (%i) is closed", cb->cli_fd_read);
                        
                        return 0;
                }
        }else{
                dbg_printf("buf not emptied, socket(%d)",cb->cli_fd_read);
                return ERR_BUF;
        }
        return 0;
}

int cgi_recv_wrapper(cli_cb_t *cb)
{
        int readctr;
        int ret;
        if(cb->cgi_parent->buf_out_ctr == -1){
                if((readctr = read(cb->cli_fd_read, 
                                   cb->cgi_parent->buf_out,
                                   BUF_OUT_SIZE)) > 0){
                        dbg_printf("read from cgi executable, readctr(%d)",
                                   readctr);
                        cb->cgi_parent->buf_out_ctr = readctr;
                        cb->cgi_parent->buf_out[readctr] = 0;
                        
                }else{
                        dbg_printf("close cgi cli cb(%d)", cb->cli_fd_read);
                        if((ret = cb->mthd.close(cb)) < 0){
                                err_printf("close cgi cb failed, ret = 0x%x",
                                           -ret);
                                return ret;
                        }
                }
        }        
        return 0;

}



static int tcp_send_wrapper(cli_cb_t *cb)
{            
        int sendctr;
        if(cb->buf_out_ctr != -1){   
                if((sendctr = send(cb->cli_fd_write, cb->buf_out, 
                                   cb->buf_out_ctr, 0))
                   != cb->buf_out_ctr){
                        cb->mthd.close(cb);

                        err_printf("Error sending to client.\n");
                        
                        return ERR_SEND;
                }else{
                        dbg_printf("buf sent, conn (%d), ctr(%d)", 
                                   cb->cli_fd_write,
                                   cb->buf_out_ctr);
                        cb->buf_out_ctr = -1;
                }
        }
        return 0;
}


static int ssl_send_wrapper(cli_cb_t *cb)
{            
        int sendctr;
        if(cb->buf_out_ctr != -1){   
                if((sendctr = SSL_write(cb->ssl, cb->buf_out, 
                                        cb->buf_out_ctr))
                   != cb->buf_out_ctr){
                        cb->mthd.close(cb);
                        
                        err_printf("send_ctr (%d), buf_out_ctr(%d).\n", 
                                   sendctr, 
                                   cb->buf_out_ctr);

                        return ERR_SEND;
                }else{
                        dbg_printf("buf sent, conn (%d), ctr(%d)", 
                                   cb->cli_fd_write,
                                   cb->buf_out_ctr);
                        cb->buf_out_ctr = -1;
                }
        }
        return 0;
}


static int cgi_send_wrapper(cli_cb_t *cb)
{
        int sendctr;
        if(cb->curr_req_msg->msg_body_len != 0){
                if((sendctr = write(cb->cli_fd_write, 
                                    cb->curr_req_msg->msg_body, 
                                    cb->curr_req_msg->msg_body_len))
                   != cb->curr_req_msg->msg_body_len){
                        cb->mthd.close(cb);

                        err_printf("Error sending to client.\n");
                        
                        return ERR_SEND;
                }else{
                        dbg_printf("buf sent, conn (%d), ctr(%d)", 
                                   cb->cli_fd_write,
                                   cb->curr_req_msg->msg_body_len);
                        cb->curr_req_msg->msg_body_len = 0;
                        free(cb->curr_req_msg->msg_body);
                }
        }
        return 0;
}




int kill_connections(void)
{
    int i;
    cli_cb_t *cb, *cb_next;
    int ret = 0;
    /* span the entire cli_list, 1. close existing connection; 2. free
     * existing control block
     */
    for (i = 0; i < HASH_SIZE; i++){
        list_for_each_entry_safe(cb, cb_next, &cli_read_list[i], cli_rlink){
                if((ret = cb->mthd.close(cb)) < 0){
                        err_printf("close cb failed, ret = 0x%x", -ret);
                        return ret;
                }
        }
    }
    return 0;
}

void liso_shutdown(void)
{
    int ret;
    dbg_printf("prepare to shutdown lisod");
    /* free ssl related vars */
    SSL_CTX_free(ssl_ctx);
    
    if((ret = kill_connections()) < 0){
        err_printf("close socket failed");
        exit(EXIT_FAILURE);
    }
    if(close_socket(sock_fd)){ 
        err_printf("close sock_fd failed");
        exit(EXIT_FAILURE);
    }
    /* this should never return */
    exit(0);
}

/* static int fill_rspd_hdr(char *buf_hdr, req_msg_t *req_msg) */
/* { */
    
/* } */


static int handle_pending_req_msg(cli_cb_t *cb)
{
        int ctr;
        int ret;
        if(cb->is_handle_cgi_pending){
                /* don't touch anything, just forward 
                 * the output from cgi executatble to client */
                dbg_printf("cgi pending, return");
                return 0;
        }else{
                if(cb->buf_out_ctr == -1){ /* only when the buf_out is sent */
                        if(cb->fd_pos + BUF_OUT_SIZE < cb->statbuf.st_size){
                                memcpy(cb->buf_out, cb->faddr + cb->fd_pos,
                                       BUF_OUT_SIZE);
                                cb->buf_out_ctr = BUF_OUT_SIZE;
                                cb->buf_out[cb->buf_out_ctr] = 0;
                                cb->fd_pos += BUF_OUT_SIZE;
                                cb->is_handle_req_msg_pending = 1;
                        }else{
                                ctr = cb->statbuf.st_size - 
                                        cb->fd_pos;
                                memcpy(cb->buf_out, cb->faddr + cb->fd_pos,
                                       ctr);
                                cb->buf_out_ctr = ctr;
                                cb->buf_out[cb->buf_out_ctr] = 0;
                                if(munmap(cb->faddr, cb->statbuf.st_size) < 0){
                                        err_printf("munmap failed");
                                        ret = ERR_MMAP;
                                        goto out1;
                                }
                                close(cb->rsrc_fd);
                                free(cb->curr_req_msg);
                                cb->is_handle_req_msg_pending = 0;
                        }
                }
        }
        return 0;
 out1:
        close(cb->rsrc_fd);
        free(cb->curr_req_msg);
        cb->is_handle_req_msg_pending = 0;
        return ret;
}


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
        

        

        /* copy the default folder */
        strncpy(filename, DEFAULT_FD, FILENAME_MAX_LEN);
        /* try to check whether the req url is / */
        if(strstr(req_msg->req_line.url, CGI_PREFIX) 
           == req_msg->req_line.url){
                /* try to handle cgi */
                if((ret = handle_cgi(req_msg, cb)) < 0){
                        err_printf("handle cgi failed,"
                                   "ret = 0x%x", -ret);
                        return ret;                    
                        }
                return 0;
        }else if(!strcmp(req_msg->req_line.url, FS_ROOT)){        
                strncat(filename, "index.html", FILENAME_MAX_LEN);
        }else{
                strncat(filename, req_msg->req_line.url, 
                        FILENAME_MAX_LEN);
        }
        
        dbg_printf("filename %s", filename);
        if((cb->rsrc_fd = open(filename, O_RDONLY)) < 0){
                dbg_printf("file not exist");
                /* return 404 not found */
                snprintf(buf_hdr, BUF_HDR_SIZE, 
                         "%s 404 Not Found\r\n\r\n", 
                         req_msg->req_line.ver);        
                
                strncpy(cb->buf_out, buf_hdr, BUF_OUT_SIZE);
                cb->buf_out_ctr = strlen(buf_hdr) + 1;
                dbg_printf("(buf_out)%s",cb->buf_out);
                        
        }else{       
                /* resource exist */
                if(fstat(cb->rsrc_fd, &cb->statbuf) < 0){
                        ret = ERR_FSTAT;
                        goto out2;
                }
                
                if((cb->faddr = mmap(0, cb->statbuf.st_size, 
                                     PROT_READ, MAP_SHARED, 
                                     cb->rsrc_fd, 0)) 
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
                        ctr += snprintf(buf_hdr + ctr, 
                                        BUF_HDR_SIZE - ctr,
                                        "Content-Type: text/css\r\n");
                }else if(strstr(req_msg->req_line.url, "png")){
                        ctr += snprintf(buf_hdr + ctr, 
                                        BUF_HDR_SIZE - ctr,
                                        "Content-Type: image/png\r\n");
                }else{
                        ctr += snprintf(buf_hdr + ctr, 
                                        BUF_HDR_SIZE - ctr,
                                        "Content-Type: text/html\r\n");
                }
                ctr += snprintf(buf_hdr + ctr, BUF_HDR_SIZE - ctr,
                                "Content-Length: %d\r\n", 
                                (int)cb->statbuf.st_size);
                ctr += snprintf(buf_hdr + ctr, BUF_HDR_SIZE - ctr,
                                "\r\n");
                
                int buf_hdr_len = strlen(buf_hdr);
                        
                if(buf_hdr_len > BUF_OUT_SIZE){
                        ret = ERR_HDR_TOO_LONG;
                        goto out2;                        
                }
                        
                memcpy(cb->buf_out, buf_hdr, buf_hdr_len);
                cb->buf_out[buf_hdr_len] = 0;
                dbg_printf("(but_out): %s", cb->buf_out);
                
                if(buf_hdr_len + cb->statbuf.st_size <= BUF_OUT_SIZE){
                        /* we could send out response once */
                        memcpy(cb->buf_out + buf_hdr_len, cb->faddr,
                               cb->statbuf.st_size);
                        cb->buf_out_ctr = buf_hdr_len + cb->statbuf.st_size;
                        cb->buf_out[cb->buf_out_ctr] = 0;
                        if(munmap(cb->faddr, cb->statbuf.st_size) < 0){
                                err_printf("munmap failed");
                                ret = ERR_MMAP;
                                goto out2;
                        }
                        close(cb->rsrc_fd);
                        cb->is_handle_req_msg_pending = 0;
                }else{
                        /* we send the response multiple times */
                        cb->fd_pos = BUF_OUT_SIZE - buf_hdr_len;
                        memcpy(cb->buf_out + buf_hdr_len, cb->faddr,
                               cb->fd_pos);
                        cb->buf_out_ctr = BUF_OUT_SIZE;
                        cb->buf_out[cb->buf_out_ctr] = 0;
                        cb->is_handle_req_msg_pending = 1;
                }
                        
        }
        
        return 0;
 out2:
        if(!cb->rsrc_fd)
                close(cb->rsrc_fd);

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
    if(!cb->mthd.is_handle_req_msg_pending(cb)){
            if(list_empty(&cb->req_msg_list)){
                    //dbg_printf("conn(%d) no req_msg pending", cb->cli_fd);
                    return 0;
            }

            /* if req msg list is not empty, try to handle one request */
            req_msg = list_first_entry(&cb->req_msg_list, 
                                       req_msg_t, req_msg_link);
            list_del(&req_msg->req_msg_link);
            
            /* set current req msg */
            cb->curr_req_msg = req_msg;
            cb->is_handle_req_msg_pending = 1;
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
            if(!cb->mthd.is_handle_req_msg_pending(cb))
                    free_req_msg(req_msg);
    }else{
            if((ret = handle_pending_req_msg(cb)) < 0){
                    err_printf("handle_pending_req_msg"
                                   " failed, ret = 0x%x",
                               -ret);
                    return ret;
                    
            }       
    }
    return 0;
}


int process_request(void)
{
    int i;
    int ret = 0;
    cli_cb_t *cb;
    for(i = 0; i < max_fd; i++){
        if(FD_ISSET(i, &read_wait_fds)){
                if(!(cb = get_cli_cb(i, 0))){
                        err_printf("conn(%d) doesn't exist", i);
                        return ERR_CONNECTION_NOT_EXIST;
                }
                dbg_printf("prepare to process read, conn(%d)",i);
                if(!cb->is_ssl){
                        switch(cb->type){
                        case LISTEN:
                                dbg_printf("set up new connection (%d)", 
                                           cb->cli_fd_read);
                                if((ret = cb->mthd.new_connection(cb)) < 0){
                                        return ret;
                                }
                                break;
                        case CLI:
                                if((ret = cb->mthd.recv(cb)) < 0){
                                        return ret;
                                }
                    
                                /*parse the req here */
                                if((ret = cb->mthd.parse(cb)) < 0){
                                        err_printf("parse failed, conn(%d)",i);
                                        return ret;
                                }              
                    
                                break;
                        case CGI:
                                if((ret = cb->mthd.recv(cb)) < 0){
                                        return ret;
                                }
                                break;
                        }
                }else{              /* if socket is ssl socket */
                        switch(cb->type){
                        case LISTEN:
                                dbg_printf("set up new ssl connection (%d)", 
                                           cb->cli_fd_read);
                                if((ret = cb->mthd.new_connection(cb)) < 0){
                                        return ret;
                                }
                                break;
                        case CLI:
                                if((ret = cb->mthd.recv(cb)) < 0){
                                        return ret;
                                }
                                
                                /*parse the req here */
                                if((ret = cb->mthd.parse(cb)) < 0){
                                        err_printf("parse failed, conn(%d)",i);
                                        return ret;
                                }              
                                
                                break;
                        default:
                                break;
                        }
                }
        }

        /* check those write wait fds */
        if(FD_ISSET(i, &write_wait_fds)){ /* write to this connection */
                
                if(!(cb = get_cli_cb(i, 1))){
                        err_printf("conn(%d) doesn't exist", 
                                   i);
                        return ERR_CONNECTION_NOT_EXIST;            
                }
                //                dbg_printf("write ready conn(%d)", i);
                if(!cb->is_ssl){
                        switch(cb->type){
                        case LISTEN:
                                break;
                        case CLI:
                                
                                if((ret = cb->mthd.
                                    handle_req_msg(cb)) < 0){
                                        err_printf("handle_req_msg"
                                                   " failed,"
                                                   " err = 0x%x", ret);
                                        return ret;
                                }
                                if((ret = cb->mthd.send(cb)) < 0){
                                        return ret;
                                }
                                break;
                        case CGI:
                                if((ret = cb->mthd.send(cb)) < 0){
                                        return ret;
                                }
                                break;
                        }
                }else{
                        switch(cb->type){
                        case LISTEN:
                                break;
                        case CLI:
                                if((ret = cb->mthd.
                                    handle_req_msg(cb)) < 0){
                                        err_printf("handle_req_msg"
                                                           " failed,"
                                                   " err = 0x%x", ret);
                                        return ret;
                                }
                                //dbg_printf("prepare to send");
                                if((ret = cb->mthd.send(cb)) < 0){
                                        return ret;
                                }
                                        break;
                        default:
                                break;
                        }
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

    /* daemonize the liso server */
    //daemonisze(lock_file);

    /* set up the first socket */    
    if((ret = establish_socket()) < 0){
        err_printf("establish_socket failed\n");
        return ret;
    }   

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
            liso_shutdown();
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

