//
// Created by yll20 on 2023/04/18.
//
#include <string>
#include <cstring>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <pthread.h>
#include <shadow.h>

#include <iostream>

#include "VPNServer.h"
#include "utils.h"

VPNServer::VPNServer(std::string bind_ip, int bind_port, std::string ca_path, std::string cert_path,
                     std::string key_path) {
    this->bind_ip = std::move(bind_ip);
    this->bind_port = bind_port;
    this->ca_path = std::move(ca_path);
    this->cert_path = std::move(cert_path);
    this->key_path = std::move(key_path);
}

VPNServer::~VPNServer() = default;

SSL_CTX *server_ssl_init(const char* CA_PATH, const char* CERT_PATH, const char* KEY_PATH) {
    SSL_CTX *ctx;

    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_load_verify_locations(ctx, CA_PATH, nullptr);// set default locations for trusted CA certificates

    // Step 2: Set up the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_PATH, SSL_FILETYPE_PEM) <=
        0) {//loads the certificate for use with Secure Sockets Layer (SSL) sessions using a specific context (CTX) structure.
        fprintf(stderr, "server cert use error!\n");
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_PATH, SSL_FILETYPE_PEM) <=
        0) {// loads the private key for use with Secure Sockets Layer (SSL) sessions using a specific context (CTX) structure.
        fprintf(stderr, "server key use error!\n");
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    if (!SSL_CTX_check_private_key(
            ctx)) {// verifies that the private key agrees with the corresponding public key in the certificate associated with a specific context (CTX) structure.
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(5);
    }
    return ctx;
}

int setup_tcp_server(const std::string &bind_ip, int bind_port) {
    auto sa_server = (struct sockaddr_in*)malloc(sizeof(sockaddr_in));
    int listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket")
    memset(sa_server, '\0', sizeof(sockaddr_in));
    sa_server->sin_family = AF_INET;
    inet_aton(bind_ip.c_str(), &(sa_server->sin_addr));
    sa_server->sin_port = htons(bind_port);
    int err = bind(listen_sock, (struct sockaddr *) sa_server, sizeof(sockaddr_in));
    CHK_ERR(err, "bind")
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen")
    return listen_sock;
}

int accept_tcp_client(int listen_sock) {
    auto clientAddr = (struct sockaddr_in*) malloc(sizeof(sockaddr_in));
    socklen_t clientAddrLen = sizeof(struct sockaddr_in);
    int client_sock = accept(listen_sock, (struct sockaddr *) clientAddr, &clientAddrLen);
    std::cout<< client_sock <<std::endl;
    if (client_sock == -1) {
        fprintf(stderr, "error accept client!\n");
        return -1;
    }
    fprintf(stdout, "get a connect request! s.ip is %s s.port is %d\n", inet_ntoa(clientAddr->sin_addr),
            clientAddr->sin_port);
    return client_sock;
}

int verify(SSL * ssl){
    // username and password
    char user_message[]="Please input username: ";
    SSL_write(ssl,user_message,static_cast<int>(strlen(user_message))+1);// writes application data across a Secure Sockets Layer (SSL) session.
    char username[BUFFER_SIZE];
    SSL_read(ssl,username,BUFFER_SIZE);
    char password_message[]="Please input password: ";
    SSL_write(ssl,password_message,static_cast<int>(strlen(password_message))+1);
    char password[BUFFER_SIZE];
    SSL_read(ssl,password,BUFFER_SIZE);
    std::cout<<username<<" "<<password<<std::endl;
    // check
    struct spwd *pw = getspnam(username);    //get account info from shadow file
    if (pw == nullptr){// the user doesn't exist
        char no[] = "Client verify failed";
        SSL_write(ssl, no, static_cast<int>(strlen(no))+1);
        fprintf(stderr,"error! user doesn't exist\n");
        return -1;
    }
    char *enc_passwd = crypt(password, pw->sp_pwdp);
    if (strcmp(enc_passwd, pw->sp_pwdp) != 0) {
        char no[] = "Client verify failed";
        SSL_write(ssl, no, static_cast<int>(strlen(no))+1);
        fprintf(stderr,"error! password\n");
        return -1;
    }
    char yes[] = "Client verify succeed";
    SSL_write(ssl, yes, static_cast<int>(strlen(yes))+1);
    return 0;
}

struct param {
    int client_sock;
    const char* ca_path;
    const char*  cert_path;
    const char*  key_path;
};

pthread_mutex_t mutex;

int create_tun_device(int* virtual_ip){
    auto ifr = (struct ifreq *)malloc(sizeof(ifreq));
    memset(ifr, 0, sizeof(ifreq));

    ifr->ifr_flags = IFF_TUN | IFF_NO_PI;
    //IFF_TUN:create a tun device
    //IFF_NO_PI:Do not provide packet information

    //create a tun device
    //find a name. lock
    pthread_mutex_lock(&mutex);
    int tun_fd = open("/dev/net/tun", O_RDWR);
    pthread_mutex_unlock(&mutex);
    if (tun_fd == -1) {
        fprintf(stderr,"error! open TUN failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }

    //register device work-model
    int ret = ioctl(tun_fd, TUNSETIFF, ifr);
    if (ret == -1) {
        fprintf(stderr,"error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }

    //tun id
    // int tunId = atoi(ifr.ifr_name+3);
    int tunId = static_cast<int>(strtol(ifr->ifr_name+3, nullptr, 10));
    if(tunId >= 127) {
        fprintf(stderr,"error! exceed the maximum number of clients!\n");
        return -1;
    }

    //client_virtual_ip=tunID+127,target_virtual_ip=tunID+1
    char cmd[1024];
    sprintf(cmd, "ip addr add 192.168.53.%d/24 dev tun%d",tunId+1,tunId);
    //sprintf(cmd,"ifconfig tun%d 192.168.53.%d/24 up",tunId,tunId+1);
    //route config
    int err;
    err = system(cmd);
    if (err == -1) {
        fprintf(stderr,"error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    sprintf(cmd, "ip link set tun%d up",tunId);
    err = system(cmd);
    if (err == -1) {
        fprintf(stderr,"error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    //sprintf(cmd,"route add -host 192.168.53.%d tun%d",tunId+127,tunId); // target -> client route
    sprintf(cmd, "ip route add 192.168.53.%d/32 dev tun%d",tunId+127,tunId);
    err = system(cmd);
    if (err == -1) {
        fprintf(stderr,"error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    err = system("sysctl net.ipv4.ip_forward=1");
    if (err == -1) {
        fprintf(stderr,"error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }

    *virtual_ip = tunId + 127;   //client_virtual_ip
    return tun_fd;
}

void select_tun(SSL* ssl, int sock_fd, int tun_fd){
    char buf[BUFFER_SIZE];
    int len;
    while(true){
        fd_set read_fd;// bitmap
        FD_ZERO(&read_fd);
        FD_SET(sock_fd,&read_fd);
        FD_SET(tun_fd,&read_fd);
        select(FD_SETSIZE,&read_fd,nullptr,nullptr,nullptr);
        // target -> client
        if(FD_ISSET(tun_fd,&read_fd)){
            memset(buf,0,strlen(buf));
            len = static_cast<int>(read(tun_fd,buf,BUFFER_SIZE));
            buf[len] = '\0';
            SSL_write(ssl,buf,len);
        }
        // client -> target
        if(FD_ISSET(sock_fd,&read_fd)){
            memset(buf,0,strlen(buf));
            len = SSL_read(ssl,buf,BUFFER_SIZE);
            if(len==0){
                fprintf(stderr,"the ssl socket close!\n");
                return;
            }
            buf[len]='\0';
            long err = write(tun_fd,buf,len);
            if(err==-1){
                fprintf(stderr,"error! write to tun device failed! (%d: %s)\n", errno, strerror(errno));
            }
        }
    }
}

void* process_connection(void *arg) {
    struct param _param = *(struct param *)arg;

    SSL_CTX *ctx = server_ssl_init(_param.ca_path, _param.cert_path, _param.key_path);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, _param.client_sock);

    int err = SSL_accept(ssl);
    if (err <= 0) {
        err = SSL_get_error(ssl, err);
        fprintf(stderr, "error! SSL_accept return fail error:%d!\n", err);
        perror("Error during SSL_accept");
        ERR_print_errors_fp(stderr);
        goto error_exit;
    }
    fprintf(stdout, "SSL_accept success!\n");

    int virtual_ip;
    int tun_fd;
    // verify client
    if (verify(ssl)!=0) {
        goto error_exit;
    }
    // create tun device
    tun_fd = create_tun_device(&virtual_ip);
    if (tun_fd == -1) {
        goto error_exit;
    }
    // send virtual ip to client
    char virtual_ip_str[16];
    sprintf(virtual_ip_str, "%d", virtual_ip);
    SSL_write(ssl, virtual_ip_str, static_cast<int>(strlen(virtual_ip_str)+1));

    // start to transfer data
    select_tun(ssl, _param.client_sock, tun_fd);

    close(tun_fd);
error_exit:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(_param.client_sock);
    return nullptr;
}

[[noreturn]] void VPNServer::Listen() {
    int listen_sock = setup_tcp_server(bind_ip, bind_port);

    while (true) {
        int client_sock = accept_tcp_client(listen_sock);
        if (client_sock == -1) {
            fprintf(stderr, "error! client_sock return fail!\n");
            continue;
        }
        auto client_arg = (struct param*)malloc(sizeof(struct param));
        client_arg->client_sock = client_sock;
        client_arg->ca_path = this->ca_path.c_str();
        client_arg->cert_path = this->cert_path.c_str();
        client_arg->key_path = this->key_path.c_str();
        pthread_t tid;
        int ret = pthread_create(&tid, nullptr, process_connection, (void *) client_arg);
        if (ret != 0) {
            perror("pthread_create failed");
        }
    }
}
