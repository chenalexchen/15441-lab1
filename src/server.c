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

#include "server_define.h"
#include "list.h"
#include "debug_define.h"






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



static int init_fds(fd_set *read, fd_set *write);
static void reelect_max_fd(void);



/** helper function to reelect max fd after one of fd is killed */
static void reelect_max_fd(void)
{
    int i = max_fd - 1;
    while(!(FD_ISSET(i, &read_fds) ||
            FD_ISSET(i, &write_fds)) &&
          i > 0){i--;}
    max_fd = i + 1;
    dbg_printf("new max fd (%d)", max_fd);
    return;
}


static void init_global_variable(void)
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
    memset(cli_cb->buf, 0, BUF_SIZE);
    cli_cb->buf_ctr = 0;
    /* insert the client cb into hash table */
    list_add_tail(&cli_cb->cli_link, &cli_list[cli_fd % HASH_SIZE]);
    return 0;
}

static void free_cli_cb(cli_cb_t *cli_cb)
{
    list_del(&cli_cb->cli_link);
    free(cli_cb);
    return;
}


static int is_buf_empty(cli_cb_t *cli_cb)
{
    return cli_cb->buf_ctr == 0;
}



static void set_buf_ctr(cli_cb_t *cli_cb, int ctr)
{
    cli_cb->buf_ctr = ctr;
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
        return EXIT_FAILURE;
    }
    
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(ECHO_PORT);
    sock_addr.sin_addr.s_addr = INADDR_ANY;
    
    /* servers bind sockets to ports---notify the OS they accept connections */
    if (bind(sock, (struct sockaddr *) &sock_addr, sizeof(sock_addr))){
        close_socket(sock);
        fprintf(stderr, "Failed binding socket.\n");
        return EXIT_FAILURE;
    }
    
    if (listen(sock, 5)){
        close_socket(sock);
        fprintf(stderr, "Error listening on socket.\n");
        return EXIT_FAILURE;
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

static int process_request(void)
{
    int i;
    socklen_t cli_size;
    struct sockaddr_in cli_addr; 
    int cli_sock;
    cli_cb_t *cb;
    int readctr = 0;
    int ret = 0;
    for(i = 0; i < max_fd; i++){
        if(FD_ISSET(i, &read_wait_fds)){
            if(is_new_connection(i)){   /* setup a new connection */
                dbg_printf("set up new connection (%d)", i);
                cli_size = sizeof(cli_addr);
                if ((cli_sock = accept(i, (struct sockaddr *) &cli_addr,
                                       &cli_size)) == -1) {
                    close(i);
                    err_printf("socket accept failure\n");
                    return EXIT_FAILURE;
                }
                cb = (cli_cb_t *) malloc(sizeof(cli_cb_t));
                if(cb == NULL){
                    
                    /* TODO: no more space for additional connection,
                     * fix the server by refuse this connection */

                    return EXIT_FAILURE;
                }
                /* init control block */
                if((ret = init_cli_cb(cb, &cli_addr, cli_sock)) < 0){
                    return EXIT_FAILURE;
                }
                /* add fd into both read and write fd */
                insert_fd(cli_sock, &read_fds);
                insert_fd(cli_sock, &write_fds);
            }else{                     /* read from this connection */
                if((cb = get_cli_cb(i)) !=NULL){
                    if(is_buf_empty(cb)){
                        if((readctr = recv(cb->cli_fd, cb->buf, BUF_SIZE, 0)) 
                           > 0){
                            dbg_printf("reading socket (%i), readctr(%d)",
                                       i, readctr);
                            set_buf_ctr(cb, readctr);
                            /* then do nothing */
                        }else{
                            /* if no reading is availale, return NULL */
                            close_socket(cb->cli_fd);
                            free_cli_cb(cb);
                            dbg_printf("conn (%i) is closed", i);
                        }
                    }else{
                        dbg_printf("buf not written, socket(%d)",i);
                    }
                }else{
                    err_printf("conn (%d) doesn't exist", i);
                    return EXIT_FAILURE;
                }
            }
        }

        /* check those write wait fds */
        if(FD_ISSET(i, &write_wait_fds)){ /* write to this connection */
            if((cb = get_cli_cb(i)) !=NULL){
                if(!is_buf_empty(cb)){
                    dbg_printf("writing socket (%i)",i);
                    if((readctr = send(cb->cli_fd, cb->buf, cb->buf_ctr, 0))
                       != cb->buf_ctr){
                        close_socket(cb->cli_fd);
                        /* free cli_cb */
                        free_cli_cb(cb);
                        err_printf("Error sending to client.\n");
                        return EXIT_FAILURE;
                    }else{
                        dbg_printf("buf sent, conn (%d), ctr(%d)", i, 
                                   cb->buf_ctr);
                        memset(cb->buf, 0, BUF_SIZE);
                        set_buf_ctr(cb, 0);
                    }
                }
            }else{
                err_printf("conn (%d) doesn't exist", i);
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
    init_global_variable();

    cprintf("----- Echo Server -----\n");
    
    if((sock_fd = establish_socket()) < 0){
        err_printf("establish_socket failed\n");
        return sock_fd;
    }
    
    
    insert_fd(sock_fd, &read_fds);
    
    dbg_printf("socket established\n");
    
    while(1){
        while( (num = select_wrapper(&time)) == 0){
            /* if time out */
            cprintf(".");
        }
        if(num == -1){
            /* if select is interrutped by signal */
            cprintf("signal received, exit ...");
            if(close_socket(sock_fd)){
                err_printf("close sock_fd failed");
                return EXIT_FAILURE;
            }
            return EXIT_SUCCESS;
        }

        if((ret = process_request()) < 0){
            err_printf("error when processing request\n");
            return ret;
        }
    }
    /* should not reach here */ 
    err_printf("should not reach here");
    return EXIT_FAILURE;

}
