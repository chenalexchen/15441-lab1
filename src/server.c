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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
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
//static int sock_fd = -1;
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


/* for tcp cli_cb_mthd_t */
static int tcp_new_connection(cli_cb_base_t *cb);
static int listen_tcp_close(cli_cb_base_t *cb);
static void listen_tcp_destroy(cli_cb_base_t *cb);

static int tcp_recv_wrapper(cli_cb_base_t *cb);
static int tcp_send_wrapper(cli_cb_base_t *cb);
static int tcp_close_socket(cli_cb_base_t *cb);
static void tcp_destroy(cli_cb_base_t *cb);


static int ssl_new_connection(cli_cb_base_t *cb);
static int listen_ssl_close(cli_cb_base_t *cb);
static void listen_ssl_destroy(cli_cb_base_t *cb);


static int ssl_recv_wrapper(cli_cb_base_t *cb);
static int ssl_send_wrapper(cli_cb_base_t *cb);
static int ssl_close_socket(cli_cb_base_t *cb);
static void ssl_destroy(cli_cb_base_t *cb);


static int cgi_recv_wrapper(cli_cb_base_t *cb);
static int cgi_send_wrapper(cli_cb_base_t *cb);
static int cgi_close(cli_cb_base_t *cb);
static int cgi_close_write(cli_cb_base_t *cb);
static int cgi_close_read(cli_cb_base_t *cb);
static void cgi_destroy(cli_cb_base_t *cb);


static int process_generic(cli_cb_base_t *cb, int read_ready, int write_ready);
static int handle_req_msg(cli_cb_base_t *cb);

static void clear_req_msg_list(struct list_head *list);



int is_buf_empty(char *buf, int ctr)
{
        return ctr == 0;
}

void make_buf_empty(char *buf, int *ctr)
{
        buf[0] = 0;
        *ctr = 0;
}

static int process_generic(cli_cb_base_t *cb, int read_ready, int write_ready)
{
        int ret;
        if(cb->mthd.parse && read_ready){
                if((ret = cb->mthd.parse(cb)) < 0){
                        err_printf("parse failed");
                        return ret;
                }
        }
        if(cb->mthd.handle_req_msg && write_ready){
                if((ret = cb->mthd.handle_req_msg(cb)) < 0){
                        err_printf("hanlde req msg failed");
                        return ret; 
                }
        }
        return 0;
}


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

static void register_cli_cb(cli_cb_base_t *cli_cb, int fd, int rw)
{
        if(!rw){ /* read */
                list_add_tail(&cli_cb->cli_rlink, 
                              &cli_read_list[fd % HASH_SIZE]);
                insert_fd(fd, &read_fds);
        }else{
                list_add_tail(&cli_cb->cli_wlink,
                              &cli_write_list[fd % HASH_SIZE]);
                insert_fd(fd, &write_fds);
        }
        return;
}

static int init_cli_cb_listen_tcp(cli_cb_base_t *cli_cb, 
                              int fd)
{
        cli_cb_listen_tcp_t *cli_cb_listen = (cli_cb_listen_tcp_t *)cli_cb;
        cli_cb_listen->cli_fd = fd;
        register_cli_cb(cli_cb, fd, 0);

        /* init listen method */
        cli_cb->mthd.recv = tcp_new_connection;
        cli_cb->mthd.close = listen_tcp_close;
        cli_cb->mthd.destroy = listen_tcp_destroy;

        cli_cb->mthd.send = NULL;
        cli_cb->mthd.close_read = NULL;
        cli_cb->mthd.close_write = NULL;
        cli_cb->mthd.parse = NULL;
        cli_cb->mthd.handle_req_msg = NULL;
        cli_cb->mthd.process = NULL;

        return 0;
}

static int init_cli_cb_tcp(cli_cb_base_t *cli_cb,
                           struct sockaddr_in *addr,
                           int fd)
{
        cli_cb_tcp_t *cli_cb_tcp = (cli_cb_tcp_t *)cli_cb;
       
        cli_cb_tcp->cli_addr = (*addr);
        
        dbg_printf("cli_addr:%s", inet_ntoa(cli_cb_tcp->cli_addr.sin_addr));
        dbg_printf("addr: %s", inet_ntoa(addr->sin_addr));
        cli_cb_tcp->cli_fd = fd;
        /* init various buffers */
        memset(cli_cb_tcp->buf_in, 0, BUF_IN_SIZE + 1);
        cli_cb_tcp->buf_in_ctr = 0;
        memset(cli_cb_tcp->buf_proc, 0, BUF_PROC_SIZE + 1);
        cli_cb_tcp->buf_proc_ctr = 0;
        memset(cli_cb_tcp->buf_out, 0, BUF_OUT_SIZE + 1);
        cli_cb_tcp->buf_out_ctr = 0;

        INIT_LIST_HEAD(&cli_cb_tcp->req_msg_list);
    
        /* register cli cb */
        register_cli_cb(cli_cb, fd, 0);
        register_cli_cb(cli_cb, fd, 1);

        cli_cb_tcp->is_send_pending = 0;
        cli_cb_tcp->is_cgi_pending = 0;
        
        /* init tcp method */        
        cli_cb->mthd.recv = tcp_recv_wrapper;
        cli_cb->mthd.send = tcp_send_wrapper;
        cli_cb->mthd.close = tcp_close_socket;
        cli_cb->mthd.destroy = tcp_destroy;

        cli_cb->mthd.parse = parse_generic;
        cli_cb->mthd.handle_req_msg = handle_req_msg;
        cli_cb->mthd.process = process_generic;
        
        cli_cb->mthd.close_read = NULL;
        cli_cb->mthd.close_write = NULL;
        return 0;
}


static int init_cli_cb_ssl(cli_cb_base_t *cli_cb,
                           struct sockaddr_in *addr,
                           int fd)
{
        int ret;
        if((ret = init_cli_cb_tcp(cli_cb, addr, fd)) < 0){
                return ret;
        }
        /* re-init the ssl mthd */
        cli_cb->mthd.recv = ssl_recv_wrapper;
        cli_cb->mthd.send = ssl_send_wrapper;
        cli_cb->mthd.close = ssl_close_socket;
        cli_cb->mthd.destroy = ssl_destroy;
        
        return 0;
}

static int init_cli_cb_listen_ssl(cli_cb_base_t *cli_cb, int fd)
{
        int ret;
        if((ret = init_cli_cb_listen_tcp(cli_cb, fd)) < 0){
                return ret;
        }
        
        /* re-init the ssl mthd */
        cli_cb->mthd.recv = ssl_new_connection;
        cli_cb->mthd.close = listen_ssl_close;
        cli_cb->mthd.destroy = listen_ssl_destroy;
        return 0;
}


static int init_cli_cb_cgi(cli_cb_base_t *cli_cb, 
                           cli_cb_base_t *parent_cb,
                           int read_fd,
                           int write_fd)
{
        cli_cb_cgi_t *cli_cb_cgi = (cli_cb_cgi_t *)cli_cb;
        cli_cb_tcp_t *tcp_par = (cli_cb_tcp_t *)parent_cb;
        cli_cb_cgi->cli_fd_read = read_fd;
        cli_cb_cgi->cli_fd_write = write_fd;

        register_cli_cb(cli_cb, read_fd, 0);
        register_cli_cb(cli_cb, write_fd, 1);
        
        cli_cb_cgi->cgi_parent = parent_cb;
        tcp_par->is_cgi_pending = 1;
        
        dbg_printf("%s", tcp_par->curr_req_msg->msg_body);
        /* init cgi methd */
        cli_cb->mthd.recv = cgi_recv_wrapper;
        cli_cb->mthd.send = cgi_send_wrapper;
        cli_cb->mthd.close = cgi_close;
        cli_cb->mthd.close_read = cgi_close_read;
        cli_cb->mthd.close_write = cgi_close_write;
        cli_cb->mthd.destroy = cgi_destroy;

        cli_cb->mthd.process = NULL;
        cli_cb->mthd.parse = NULL;
        cli_cb->mthd.handle_req_msg = NULL;
        
        return 0;
}


int init_cli_cb(cli_cb_base_t *cli_cb, cli_cb_base_t *parent_cb,
                struct sockaddr_in *addr, 
                int cli_fd_read,
                int cli_fd_write,
                cli_cb_type_t type)
{    
        int ret = 0;
        cli_cb->type = type;
        switch(type){
        case LISTEN_TCP:
                ret = init_cli_cb_listen_tcp(cli_cb, cli_fd_read);
                break;
        case CONN_TCP:
                ret = init_cli_cb_tcp(cli_cb, addr, cli_fd_read);
                break;
        case LISTEN_SSL:
                ret = init_cli_cb_listen_ssl(cli_cb, cli_fd_read);
                break;
        case CONN_SSL:
                ret = init_cli_cb_ssl(cli_cb, addr, cli_fd_read);
                break;
        case CGI:
                ret = init_cli_cb_cgi(cli_cb, parent_cb,
                                      cli_fd_read, cli_fd_write);
                break;
        default:
                ret = ERR_INIT_CLI;
                err_printf("unknown cli cb type");
                break;
        }

        return ret;

}


static void tcp_destroy(cli_cb_base_t *cb)
{
        cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;
        
        clear_req_msg_list(&tcp_cb->req_msg_list);
        free(cb);
}

static void ssl_destroy(cli_cb_base_t *cb)
{
        cli_cb_ssl_t *ssl_cb = (cli_cb_ssl_t *)cb;
        clear_req_msg_list(&ssl_cb->tcp_base.req_msg_list);

        free(cb);
}

static void cgi_destroy(cli_cb_base_t *cb)
{
        free(cb);
}


static void clear_req_msg_list(struct list_head *list)
{
        req_msg_t *msg_curr, *msg_next;
        list_for_each_entry_safe(msg_curr, msg_next,
                                 list,
                                 req_msg_link){
                clear_req_msg(msg_curr);
                free(msg_curr);
                
        }
        return;
}


static int get_fd(cli_cb_base_t *cb, int rw)
{
        cli_cb_tcp_t *tcp_cb;
        cli_cb_listen_tcp_t *tcp_listen_cb;
        cli_cb_cgi_t *cgi_cb;
        switch(cb->type){
        case LISTEN_TCP:
        case LISTEN_SSL:
                if(!rw){
                        tcp_listen_cb = (cli_cb_listen_tcp_t *)cb;
                        
                        return tcp_listen_cb->cli_fd;
                }
                break;
        case CONN_TCP:
        case CONN_SSL:

                tcp_cb = (cli_cb_tcp_t *)cb;
                return tcp_cb->cli_fd;

        case CGI:
                cgi_cb = (cli_cb_cgi_t *)cb;
                if(!rw){
                        return cgi_cb->cli_fd_read;                        
                }else{
                        return cgi_cb->cli_fd_write;
                }
        }
        return -1;
}

cli_cb_base_t *get_cli_cb(int cli_fd, int rw)
{
        cli_cb_base_t *item;
        if(!rw){
                list_for_each_entry(item, &cli_read_list[cli_fd % HASH_SIZE], 
                                    cli_rlink){

                        if(get_fd(item, 0) == cli_fd){
                                return item;
                        }
                }
                
        }else{
                list_for_each_entry(item, &cli_write_list[cli_fd % HASH_SIZE], 
                                    cli_wlink){
                        
                        if(get_fd(item, 1) == cli_fd){
                                return item;
                        }
                }
        }
        return NULL;
}



static int close_socket(int sock)
{
        dbg_printf("close conn(%d)", sock);
        if (close(sock)){

                err_printf("Failed closing socket.\n");
                return ERR_CLOSE_SOCKET;
        }
        FD_CLR(sock, &read_fds);
        FD_CLR(sock, &write_fds);
        FD_CLR(sock, &read_wait_fds);
        FD_CLR(sock, &write_wait_fds);
        reelect_max_fd();        
        return 0;
}

static int tcp_close_socket(cli_cb_base_t *cb)
{
        cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;
        int ret;
        
        dbg_printf("close socket(%d)", tcp_cb->cli_fd);
        if((ret = close_socket(tcp_cb->cli_fd)) < 0){
                ret = ERR_CLOSE_SOCKET;
                return ret;
        }
        /* socket is closed, it is no longer searchable by 
         * its socket fd */
        list_del(&cb->cli_rlink);
        list_del(&cb->cli_wlink);

        return 0;
}

static int listen_tcp_close(cli_cb_base_t *cb)
{
        cli_cb_listen_tcp_t *listen_cb = (cli_cb_listen_tcp_t *)cb;

        int sock = listen_cb->cli_fd;

        dbg_printf("close listen conn(%d)", sock);

        FD_CLR(sock, &read_fds);
        FD_CLR(sock, &read_wait_fds);
        reelect_max_fd();        

        if (close(sock)){
                err_printf("Failed closing socket.\n");
                return ERR_CLOSE_SOCKET;
        }

        return 0;
}

static int listen_ssl_close(cli_cb_base_t *cb)
{

        return listen_tcp_close(cb);
}


static void listen_tcp_destroy(cli_cb_base_t *cb)
{
        return;
}

static void listen_ssl_destroy(cli_cb_base_t *cb)
{
        return;
}

static int ssl_close_socket(cli_cb_base_t *cb)
{
    int ret;
    
    cli_cb_ssl_t *ssl_cb = (cli_cb_ssl_t *)cb;   

    if((ret = SSL_shutdown(ssl_cb->ssl)) < 0){
            ret = ERR_CLOSE_SSL_SOCKET;
            return ret;
    }
    
    SSL_free(ssl_cb->ssl);

    return tcp_close_socket(cb);
}


static int cgi_close(cli_cb_base_t *cb)
{
        int ret;
        cli_cb_cgi_t *cgi_cb = (cli_cb_cgi_t *)cb;
        cli_cb_tcp_t *parent_cb = (cli_cb_tcp_t *)cgi_cb->cgi_parent;

        if((ret = cb->mthd.close_read(cb)) < 0 || 
           (ret = cb->mthd.close_write(cb)) < 0){
                return ret;
        }
        
        parent_cb->is_send_pending = 0;

        return 0;
}

static int cgi_close_read(cli_cb_base_t *cb)
{

        cli_cb_cgi_t *cgi_cb = (cli_cb_cgi_t *)cb;
        if(cgi_cb->cli_fd_read != -1){

                dbg_printf("close conn(%d)", cgi_cb->cli_fd_read);
                
                if (close(cgi_cb->cli_fd_read)){
                        
                        err_printf("Failed closing socket.\n");
                        return ERR_CLOSE_FD;
                }
                FD_CLR(cgi_cb->cli_fd_read, &read_fds);
                FD_CLR(cgi_cb->cli_fd_read, &read_wait_fds);        
                reelect_max_fd();        
                list_del(&cb->cli_rlink);
                cgi_cb->cli_fd_read = -1;
                return 0;
        }
        return 0;
}


static int cgi_close_write(cli_cb_base_t *cb)
{

        cli_cb_cgi_t *cgi_cb = (cli_cb_cgi_t *)cb;
        if(cgi_cb->cli_fd_write != -1){
                dbg_printf("close conn(%d)", cgi_cb->cli_fd_write);
                
                if (close(cgi_cb->cli_fd_write)){
                        err_printf("Failed closing socket.\n");
                        return ERR_CLOSE_FD;
                }
                FD_CLR(cgi_cb->cli_fd_write, &write_fds);
                FD_CLR(cgi_cb->cli_fd_write, &write_wait_fds);
                reelect_max_fd();        
                list_del(&cb->cli_wlink);
                cgi_cb->cli_fd_write = -1;
                return 0;
        }
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
    cli_cb_base_t *cb;
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


    cb = (cli_cb_base_t *) malloc(sizeof(cli_cb_listen_tcp_t));
    if(cb == NULL){
        return ERR_NO_MEM;
    }
    /* init control block */
    if((ret = init_cli_cb(cb, NULL, NULL, sock, sock, LISTEN_TCP)) < 0){
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

    cb = (cli_cb_base_t *) malloc(sizeof(cli_cb_listen_ssl_t));
    if(cb == NULL){
        return ERR_NO_MEM;
    }
    /* init control block */
    if((ret = init_cli_cb(cb, NULL, NULL, sock, sock, LISTEN_SSL)) < 0){
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


static int tcp_new_connection(cli_cb_base_t *cb)
{
        cli_cb_listen_tcp_t *listen_cb = (cli_cb_listen_tcp_t *)cb;
        cli_cb_tcp_t *tcp_cb_new;
        socklen_t cli_size;
        struct sockaddr_in cli_addr;
        int cli_sock;

        int ret;
        cli_size = sizeof(cli_addr);
        if ((cli_sock = accept(listen_cb->cli_fd, 
                               (struct sockaddr *) &cli_addr,
                               &cli_size)) == -1) {
                if((ret = cb->mthd.close(cb)) < 0){
                        err_printf("close tcp socket error");
                        return ret;
                }
                err_printf("socket accept failure\n");
                cb->mthd.destroy(cb);                
                return ERR_ACCEPT_FAILURE;
        }

        tcp_cb_new = (cli_cb_tcp_t *) malloc(sizeof(cli_cb_tcp_t));
        if(tcp_cb_new == NULL){
                
                /* TODO: no more space for additional connection,
                 * fix the server by refuse this connection */
                
                return ERR_NO_MEM;
        }
        /* init control block */
        if((ret = init_cli_cb(&(tcp_cb_new->base), NULL,
                              &cli_addr, cli_sock, 
                              cli_sock, CONN_TCP)) < 0){
                free(tcp_cb_new);
                return ret;
        }
        
        dbg_printf("conn(%d) create conn(%d)", listen_cb->cli_fd, 
                   tcp_cb_new->cli_fd);
        return 0;
}


static int ssl_new_connection(cli_cb_base_t *cb)
{
        socklen_t cli_size;
        struct sockaddr_in cli_addr;
        int cli_sock;
        cli_cb_listen_ssl_t *listen_cb = (cli_cb_listen_ssl_t *)cb;
        cli_cb_ssl_t *ssl_cb_new;
        cli_cb_tcp_t *tcp_cb_new;
        cli_cb_base_t *cb_new;
        int ret;
        
        cli_size = sizeof(cli_addr);
        dbg_printf("accept fd(%d)", listen_cb->cli_fd);
        if ((cli_sock = accept(listen_cb->cli_fd, (struct sockaddr *) &cli_addr,
                               &cli_size)) == -1) {
                if((ret = cb->mthd.close(cb)) < 0){
                        err_printf("close socket failed, ret = 0x%x", -ret);
                        return ret;
                }
                err_printf("socket accept failure\n");
                cb->mthd.destroy(cb);
                return ERR_ACCEPT_FAILURE;
    }
    ssl_cb_new = (cli_cb_ssl_t *) malloc(sizeof(cli_cb_ssl_t));
    if(ssl_cb_new == NULL){
        return ERR_NO_MEM;
    }
    tcp_cb_new = (cli_cb_tcp_t *)ssl_cb_new;
    cb_new = (cli_cb_base_t *)ssl_cb_new;

    /* init control block */
    if((ret = init_cli_cb(cb_new, NULL,
                          &cli_addr, cli_sock, cli_sock, CONN_SSL)) < 0){
        free(ssl_cb_new);
        return ret;
    }

    if(!(ssl_cb_new->ssl = SSL_new(ssl_ctx))){
            if((ret = cb_new->mthd.close(cb_new)) < 0){
                        err_printf("close socket failed, ret = 0x%x", -ret);
                        return ret;
            }
            err_printf("socket accept failure\n");
            cb_new->mthd.destroy(cb_new);            
            return ERR_SSL_NEW;
    }
    dbg_printf("SSL_new succeed");
    SSL_set_fd(ssl_cb_new->ssl, tcp_cb_new->cli_fd);
    dbg_printf("set fd(%d) succeed", tcp_cb_new->cli_fd);

    if((ret = SSL_accept(ssl_cb_new->ssl)) < 0){
        ERR_print_errors_fp(stderr);
        return ERR_SSL_ACCEPT;
    }

    dbg_printf("SSL connection using %s\n", SSL_get_cipher(ssl_cb_new->ssl));


    dbg_printf("conn(%d) create conn(%d)", listen_cb->cli_fd, 
               tcp_cb_new->cli_fd);
    return 0;
}


int tcp_recv_wrapper(cli_cb_base_t *cb)
{
        int readctr;
        cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;
        if(is_buf_empty(tcp_cb->buf_in, tcp_cb->buf_in_ctr)){
                if((readctr = recv(tcp_cb->cli_fd, tcp_cb->buf_in, 
                                   BUF_IN_SIZE, 0)) 
                   > 0){
                        dbg_printf("reading socket (%i), readctr(%d)",
                                   tcp_cb->cli_fd, readctr);
                        /* add null terminator to cb->buf_in */
                        tcp_cb->buf_in_ctr = readctr;
                        tcp_cb->buf_in[readctr] = 0;                        
                        /* then do nothing */

                }else{
                    /* if no reading is availale, return NULL */
                        cb->mthd.close(cb);
                        dbg_printf("conn (%i) is closed", tcp_cb->cli_fd);
                        
                        return 0;
                }
        }
        return 0;
}


int ssl_recv_wrapper(cli_cb_base_t *cb)
{
        int readctr;
        cli_cb_ssl_t *ssl_cb = (cli_cb_ssl_t *)cb;
        cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;

        if(is_buf_empty(tcp_cb->buf_in, tcp_cb->buf_out_ctr)){
                if((readctr = SSL_read(ssl_cb->ssl, tcp_cb->buf_in, 
                                       BUF_IN_SIZE)) 
                   > 0){
                        dbg_printf("reading socket (%i), readctr(%d)",
                                   tcp_cb->cli_fd, readctr);
                        /* add null terminator to cb->buf_in */
                        tcp_cb->buf_in_ctr = readctr;
                        tcp_cb->buf_in[readctr] = 0;
                        /* then do nothing */
                }else{
                        /* if no reading is availale, return NULL */
                        cb->mthd.close(cb);
                        dbg_printf("conn (%i) is closed", tcp_cb->cli_fd);
                        
                        return 0;
                }
        }
        return 0;
}

int cgi_recv_wrapper(cli_cb_base_t *cb)
{
        int readctr;
        int ret;

        cli_cb_cgi_t *cgi_cb = (cli_cb_cgi_t *)cb;
        cli_cb_tcp_t *tcp_par = (cli_cb_tcp_t *)(cgi_cb->cgi_parent);
        if(is_buf_empty(tcp_par->buf_out, tcp_par->buf_out_ctr)){
                if((readctr = read(cgi_cb->cli_fd_read, 
                                   tcp_par->buf_out,
                                   BUF_OUT_SIZE)) > 0){
                        dbg_printf("read from cgi executable, readctr(%d)",
                                   readctr);
                        tcp_par->buf_out_ctr = readctr;
                        tcp_par->buf_out[readctr] = 0;
                        
                }else{
                        dbg_printf("close cgi cli cb(%d), readctr(%d)",
                                   cgi_cb->cli_fd_read,
                                   readctr);
                        if((ret = cb->mthd.close(cb)) < 0){
                                err_printf("close cgi cb failed, ret = 0x%x",
                                           -ret);
                                return ret;
                        }
                        /* close parent connection */
                        tcp_par->is_cgi_pending = 0;
                        /* if((ret = cgi_cb->cgi_parent->mthd.close(cgi_cb-> */
                        /*                                          cgi_parent)) */
                        /*    < 0){ */
                        /*         err_printf("close cb failed, ret = 0x%x", */
                        /*                    -ret); */
                        /*         return ret; */
                        /* } */
                }
        }        
        return 0;
}



static int tcp_send_wrapper(cli_cb_base_t *cb)
{            
        int sendctr;
        cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;
        if(!is_buf_empty(tcp_cb->buf_out, tcp_cb->buf_out_ctr)){   
                dbg_printf("%s",tcp_cb->buf_out);
                if((sendctr = send(tcp_cb->cli_fd, tcp_cb->buf_out, 
                                   tcp_cb->buf_out_ctr, 0))
                   != tcp_cb->buf_out_ctr){
                        cb->mthd.close(cb);

                        err_printf("Error sending to client.\n");
                        
                        return ERR_SEND;
                }else{
                        dbg_printf("buf sent, conn (%d), ctr(%d)", 
                                   tcp_cb->cli_fd,
                                   tcp_cb->buf_out_ctr);
                        make_buf_empty(tcp_cb->buf_out, &tcp_cb->buf_out_ctr);
                }
        }
        return 0;
}


static int ssl_send_wrapper(cli_cb_base_t *cb)
{            
        int sendctr;
        cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;
        cli_cb_ssl_t *ssl_cb = (cli_cb_ssl_t *)cb;
        if(!is_buf_empty(tcp_cb->buf_out, tcp_cb->buf_out_ctr)){   
                if((sendctr = SSL_write(ssl_cb->ssl, tcp_cb->buf_out, 
                                        tcp_cb->buf_out_ctr))
                   != tcp_cb->buf_out_ctr){
                        cb->mthd.close(cb);
                        err_printf("send_ctr (%d), buf_out_ctr(%d).\n", 
                                   sendctr, 
                                   tcp_cb->buf_out_ctr);
                        return ERR_SEND;
                }else{
                        dbg_printf("buf sent, conn (%d), ctr(%d)", 
                                   tcp_cb->cli_fd,
                                   tcp_cb->buf_out_ctr);
                        make_buf_empty(tcp_cb->buf_out, &tcp_cb->buf_out_ctr);
                }
        }
        return 0;
}


static int cgi_send_wrapper(cli_cb_base_t *cb)
{
        int sendctr;
        cli_cb_cgi_t *cgi_cb = (cli_cb_cgi_t *)cb;
        cli_cb_tcp_t *par_cb = (cli_cb_tcp_t *)(cgi_cb->cgi_parent);

        if(!is_buf_empty(par_cb->curr_req_msg->msg_body, 
                         par_cb->curr_req_msg->msg_body_len)){
                if((sendctr = write(cgi_cb->cli_fd_write, 
                                    par_cb->curr_req_msg->msg_body, 
                                    par_cb->curr_req_msg->msg_body_len))
                   != par_cb->curr_req_msg->msg_body_len){
                        
                        cb->mthd.close(cb);
                        err_printf("Error sending to client.\n");
                        return ERR_SEND;
                }else{
                        dbg_printf("buf sent, conn (%d), ctr(%d)", 
                                   cgi_cb->cli_fd_write,
                                   par_cb->curr_req_msg->msg_body_len);
                        dbg_printf("cgi parent (%d)", par_cb->cli_fd);
                        dbg_printf("msg_body: %s", 
                                   par_cb->curr_req_msg->msg_body);
                        make_buf_empty(par_cb->curr_req_msg->msg_body,
                                       &par_cb->curr_req_msg->msg_body_len);
                        free(par_cb->curr_req_msg->msg_body);
                        par_cb->curr_req_msg->msg_body = NULL;
                        par_cb->curr_req_msg->msg_body_len = 0;
                        cb->mthd.close_write(cb);
                }
        }else{
                dbg_printf("no message body, close cli_fd_write(%d)",
                           cgi_cb->cli_fd_write);
                cb->mthd.close_write(cb);
        }
        return 0;
}


int kill_connections(void)
{
    int i;
    cli_cb_base_t *cb, *cb_next;
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
                cb->mthd.destroy(cb);
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
    /* this should never return */
    exit(0);
}


static int handle_pending_send(cli_cb_base_t *cb)
{
        int ctr;
        int ret;
        cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;

        if(!tcp_cb->is_send_pending){
                /* don't touch anything, just forward 
                 * the output from cgi executatble to client */
                //dbg_printf("cgi pending, return");
                return 0;
        }else{
                if(is_buf_empty(tcp_cb->buf_out,
                                 tcp_cb->buf_out_ctr)){ 
                        /* only when the buf_out is sent */
                        if(tcp_cb->fd_pos + BUF_OUT_SIZE < 
                           tcp_cb->statbuf.st_size){
                                memcpy(tcp_cb->buf_out, 
                                       tcp_cb->faddr + tcp_cb->fd_pos,
                                       BUF_OUT_SIZE);
                                tcp_cb->buf_out_ctr = BUF_OUT_SIZE;
                                tcp_cb->buf_out[tcp_cb->buf_out_ctr] = 0;
                                tcp_cb->fd_pos += BUF_OUT_SIZE;
                        }else{
                                ctr = tcp_cb->statbuf.st_size - 
                                        tcp_cb->fd_pos;
                                memcpy(tcp_cb->buf_out, 
                                       tcp_cb->faddr + tcp_cb->fd_pos,
                                       ctr);
                                tcp_cb->buf_out_ctr = ctr;
                                tcp_cb->buf_out[tcp_cb->buf_out_ctr] = 0;
                                if(munmap(tcp_cb->faddr, 
                                          tcp_cb->statbuf.st_size) < 0){
                                        err_printf("munmap failed");
                                        ret = ERR_MMAP;
                                        goto out1;
                                }
                                close(tcp_cb->rsrc_fd);
                                clear_req_msg(tcp_cb->curr_req_msg);
                                free(tcp_cb->curr_req_msg);
                                tcp_cb->is_send_pending = 0;
                        }
                }
        }
        return 0;
 out1:
        close(tcp_cb->rsrc_fd);
        free(tcp_cb->curr_req_msg);
        tcp_cb->is_send_pending = 0;
        return ret;
}


static int handle_pending_cgi_send(cli_cb_base_t *cb)
{
        return 0;
}

static int handle_head_mthd(req_msg_t *req_msg, cli_cb_base_t *cb)
{
        int ret;
        /* fill in the header to return to */
        
        char filename[FILENAME_MAX_LEN];
        char buf_hdr[BUF_HDR_SIZE];
        int ctr = 0; 
        
        cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;

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
        if((tcp_cb->rsrc_fd = open(filename, O_RDONLY)) < 0){
                dbg_printf("file not exist");
                /* return 404 not found */
                snprintf(buf_hdr, BUF_HDR_SIZE, 
                         "%s 404 Not Found\r\n\r\n", 
                         req_msg->req_line.ver);        
                
                strncpy(tcp_cb->buf_out, buf_hdr, BUF_OUT_SIZE);
                tcp_cb->buf_out_ctr = strlen(buf_hdr) + 1;
                dbg_printf("(buf_out)%s",tcp_cb->buf_out);
                        
        }else{       
                /* resource exist */
                if(fstat(tcp_cb->rsrc_fd, &tcp_cb->statbuf) < 0){
                        ret = ERR_FSTAT;
                        goto out2;
                }
                
                if((tcp_cb->faddr = mmap(0, tcp_cb->statbuf.st_size, 
                                         PROT_READ, MAP_SHARED, 
                                         tcp_cb->rsrc_fd, 0)) 
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
                                (int)tcp_cb->statbuf.st_size);
                ctr += snprintf(buf_hdr + ctr, BUF_HDR_SIZE - ctr,
                                "\r\n");
                
                int buf_hdr_len = strlen(buf_hdr);
                        
                if(buf_hdr_len > BUF_OUT_SIZE){
                        ret = ERR_HDR_TOO_LONG;
                        goto out2;                        
                }
                        
                memcpy(tcp_cb->buf_out, buf_hdr, buf_hdr_len);
                tcp_cb->buf_out[buf_hdr_len] = 0;
                dbg_printf("(but_out): %s", tcp_cb->buf_out);
                if(munmap(tcp_cb->faddr, tcp_cb->statbuf.st_size) < 0){
                        err_printf("munmap failed");
                        ret = ERR_MMAP;
                        goto out2;
                }
                if(close(tcp_cb->rsrc_fd) < 0){
                        ret = ERR_CLOSE_FD;
                        return ret;
                }
                tcp_cb->is_send_pending = 0;                        
        }
        
        return 0;
 out2:
        if(!tcp_cb->rsrc_fd)
                close(tcp_cb->rsrc_fd);

        return ret;


}


static int handle_get_mthd(req_msg_t *req_msg, cli_cb_base_t *cb)
{
        int ret;
        /* fill in the header to return to */
        
        char filename[FILENAME_MAX_LEN];
        char buf_hdr[BUF_HDR_SIZE];
        int ctr = 0; 
        
        cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;

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
        if((tcp_cb->rsrc_fd = open(filename, O_RDONLY)) < 0){
                dbg_printf("file not exist");
                /* return 404 not found */
                snprintf(buf_hdr, BUF_HDR_SIZE, 
                         "%s 404 Not Found\r\n\r\n", 
                         req_msg->req_line.ver);        
                
                strncpy(tcp_cb->buf_out, buf_hdr, BUF_OUT_SIZE);
                tcp_cb->buf_out_ctr = strlen(buf_hdr) + 1;
                dbg_printf("(buf_out)%s",tcp_cb->buf_out);
                        
        }else{       
                /* resource exist */
                if(fstat(tcp_cb->rsrc_fd, &tcp_cb->statbuf) < 0){
                        ret = ERR_FSTAT;
                        goto out2;
                }
                
                if((tcp_cb->faddr = mmap(0, tcp_cb->statbuf.st_size, 
                                         PROT_READ, MAP_SHARED, 
                                         tcp_cb->rsrc_fd, 0)) 
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
                                (int)tcp_cb->statbuf.st_size);
                ctr += snprintf(buf_hdr + ctr, BUF_HDR_SIZE - ctr,
                                "\r\n");
                
                int buf_hdr_len = strlen(buf_hdr);
                        
                if(buf_hdr_len > BUF_OUT_SIZE){
                        ret = ERR_HDR_TOO_LONG;
                        goto out2;                        
                }
                        
                memcpy(tcp_cb->buf_out, buf_hdr, buf_hdr_len);
                tcp_cb->buf_out[buf_hdr_len] = 0;
                dbg_printf("(but_out): %s", tcp_cb->buf_out);
                
                if(buf_hdr_len + tcp_cb->statbuf.st_size <= BUF_OUT_SIZE){
                        /* we could send out response once */
                        memcpy(tcp_cb->buf_out + buf_hdr_len, tcp_cb->faddr,
                               tcp_cb->statbuf.st_size);
                        tcp_cb->buf_out_ctr = buf_hdr_len + 
                                tcp_cb->statbuf.st_size;
                        tcp_cb->buf_out[tcp_cb->buf_out_ctr] = 0;
                        if(munmap(tcp_cb->faddr, tcp_cb->statbuf.st_size) < 0){
                                err_printf("munmap failed");
                                ret = ERR_MMAP;
                                goto out2;
                        }
                        close(tcp_cb->rsrc_fd);
                        tcp_cb->is_send_pending = 0;
                }else{
                        /* we send the response multiple times */
                        tcp_cb->fd_pos = BUF_OUT_SIZE - buf_hdr_len;
                        memcpy(tcp_cb->buf_out + buf_hdr_len, tcp_cb->faddr,
                               tcp_cb->fd_pos);
                        tcp_cb->buf_out_ctr = BUF_OUT_SIZE;
                        tcp_cb->buf_out[tcp_cb->buf_out_ctr] = 0;
                        tcp_cb->is_send_pending = 1;
                }
                        
        }
        
        return 0;
 out2:
        if(!tcp_cb->rsrc_fd)
                close(tcp_cb->rsrc_fd);

        return ret;
}


/* currently only handle cgi call */
static int handle_post_mthd(req_msg_t *req_msg, cli_cb_base_t *cb)
{
        int ret;
        /* try to check whether the req url is / */
        if(strstr(req_msg->req_line.url, CGI_PREFIX) 
           == req_msg->req_line.url){
                /* try to handle cgi */
                if((ret = handle_cgi(req_msg, cb)) < 0){
                        err_printf("handle cgi failed,"
                                   "ret = 0x%x", -ret);
                        return ret;                    
                }
        }
        return 0;
}

static int handle_unknown_mthd(req_msg_t *req_msg, cli_cb_base_t *cb)
{
    return 0;
}

static int handle_req_msg(cli_cb_base_t *cb)
{
    req_msg_t *req_msg;
    int ret;
    cli_cb_tcp_t *tcp_cb = (cli_cb_tcp_t *)cb;
    /* if req msg list is empty */
    if(!tcp_cb->is_send_pending && !tcp_cb->is_cgi_pending){
            if(list_empty(&tcp_cb->req_msg_list)){
                    //dbg_printf("conn(%d) no req_msg pending", cb->cli_fd);
                    return 0;
            }

            /* if req msg list is not empty, try to handle one request */
            req_msg = list_first_entry(&tcp_cb->req_msg_list, 
                                       req_msg_t, req_msg_link);
            list_del(&req_msg->req_msg_link);
            
            /* set current req msg */
            tcp_cb->curr_req_msg = req_msg;

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
            if(!tcp_cb->is_send_pending && !tcp_cb->is_cgi_pending){
                    dbg_printf("req_msg is freed");
                    clear_req_msg(req_msg);
                    free(req_msg);
            }
    }else if(tcp_cb->is_send_pending){
            if((ret = handle_pending_send(cb)) < 0){
                    err_printf("handle_pending_req_msg"
                                   " failed, ret = 0x%x",
                               -ret);
                    return ret;                    
            }       
    }else{
            if((ret = handle_pending_cgi_send(cb)) < 0){
                    err_printf("handle pending cgi send failed, ret = 0x%x",
                               ret);
                    return ret;
            }

    }
    return 0;
}



int process_io(void)
{
    int i;
    int ret = 0;
    cli_cb_base_t *cb;
    int read_ready = 0;
    int write_ready = 0;

    for(i = 0; i < max_fd; i++){
            read_ready = FD_ISSET(i, &read_wait_fds);
            write_ready = FD_ISSET(i, &write_wait_fds);

            if(read_ready){                    
                    if(!(cb = get_cli_cb(i, 0))){
                            dbg_printf("read conn(%d) doesn't exist or killed",
                                       i);
                            return 0;
                    }
                    if(cb->mthd.recv){
                            if((ret = cb->mthd.recv(cb)) < 0){
                                    err_printf("recv failed, conn(%d)", i);
                                    return ret;
                            }
                    }
            }
            
            if(write_ready){
                    if(!(cb = get_cli_cb(i, 1))){
                            err_printf("write conn(%d) doesnt' exist or killed",
                                       i);
                            return 0;
                    }
                    if(cb->mthd.send){
                            if((ret = cb->mthd.send(cb)) < 0){
                                    err_printf("send failed, conn(%d)", i);
                                    return ret;
                            }
                    }
            }
            
            if(read_ready || write_ready){
                    if(cb->mthd.process){
                            if((ret = cb->mthd.process(cb, read_ready,
                                                       write_ready)) < 0){
                                    err_printf("process failed, conn(%d)", i);
                                    return ret;
                            }
                    }
            }
                
    }
    return 0;
}

static void reset_timer(struct timeval *time)
{
        time->tv_sec = TIMEOUT_TIME;
        time->tv_usec = 0;
        return;
}
static int handle_signal(void)
{
        return 0;
}

int main(int argc, char* argv[])
{
    /* set the select timeout 1s */
    struct timeval time; 
    reset_timer(&time);
    int num;
    int ret = 0;
    //int status;
    /* init global variable */
    init_global_var();

    cprintf("----- Echo Server -----\n");

    /* daemonize the liso server */
    //daemonisze(lock_file);

    /* set up the first tcp and ssl socket */    
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
            reset_timer(&time);
        }
        if(num < 0){
                /*
                 * TODO: currently, only one of the sockets is killed
                 */
                dbg_printf("signal received");
                if(handle_signal() < 0){
                        err_printf("handle signal failed");
                        return EXIT_FAILURE;
                }
                /* kill all the exiting connections */
                //            liso_shutdown();
                //            return EXIT_SUCCESS;
                //wait(&status);
                dbg_printf("errno %d", errno);
                continue;
        }

        if((ret = process_io()) < 0){
            err_printf("error(0x%x) when processing request\n", -ret);
            return EXIT_FAILURE;
        }
    }
    /* should not reach here */ 
    err_printf("should not reach here");
    return EXIT_FAILURE;
}

