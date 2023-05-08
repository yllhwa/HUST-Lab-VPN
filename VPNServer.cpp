//
// Created by yll20 on 2023/04/18.
//
#include <string>
#include <cstring>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
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
#include <sys/stat.h>
#include <dirent.h>

#include "VPNServer.h"
#include "utils.h"

VPNServer::VPNServer(std::string bind_ip, int bind_port, std::string ca_path, std::string cert_path,
                     std::string key_path, std::string virtual_ip_cidr) {
    this->bind_ip = std::move(bind_ip);
    this->bind_port = bind_port;
    this->ca_path = std::move(ca_path);
    this->cert_path = std::move(cert_path);
    this->key_path = std::move(key_path);
    this->virtual_ip_cidr = std::move(virtual_ip_cidr);
}

VPNServer::~VPNServer() = default;

SSL_CTX *server_ssl_init(const char *CA_PATH, const char *CERT_PATH, const char *KEY_PATH) {
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

int VPNServer::setupTcpServer() {
    auto sa_server = (struct sockaddr_in *) malloc(sizeof(sockaddr_in));
    int listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket")
    memset(sa_server, '\0', sizeof(sockaddr_in));
    sa_server->sin_family = AF_INET;
    inet_aton(this->bind_ip.c_str(), &(sa_server->sin_addr));
    sa_server->sin_port = htons(this->bind_port);
    int err = bind(listen_sock, (struct sockaddr *) sa_server, sizeof(sockaddr_in));
    CHK_ERR(err, "bind")
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen")
    free(sa_server);
    return listen_sock;
}

int accept_tcp_client(int listen_sock) {
    auto clientAddr = (struct sockaddr_in *) malloc(sizeof(sockaddr_in));
    socklen_t clientAddrLen = sizeof(struct sockaddr_in);
    int client_sock = accept(listen_sock, (struct sockaddr *) clientAddr, &clientAddrLen);
    std::cout << client_sock << std::endl;
    if (client_sock == -1) {
        fprintf(stderr, "error accept client!\n");
        return -1;
    }
    fprintf(stdout, "get a connect request! s.ip is %s s.port is %d\n", inet_ntoa(clientAddr->sin_addr),
            clientAddr->sin_port);
    return client_sock;
}

int verify(SSL *ssl) {
    // username and password
    char user_message[] = "Please input username: ";
    SSL_write(ssl, user_message, static_cast<int>(strlen(user_message)) +
                                 1);// writes application data across a Secure Sockets Layer (SSL) session.
    char username[BUFFER_SIZE];
    SSL_read(ssl, username, BUFFER_SIZE);
    char password_message[] = "Please input password: ";
    SSL_write(ssl, password_message, static_cast<int>(strlen(password_message)) + 1);
    char password[BUFFER_SIZE];
    SSL_read(ssl, password, BUFFER_SIZE);
    std::cout << username << " " << password << std::endl;
    // check
    struct spwd *pw = getspnam(username);    //get account info from shadow file
    if (pw == nullptr) {// the user doesn't exist
        char no[] = "Client verify failed";
        SSL_write(ssl, no, static_cast<int>(strlen(no)) + 1);
        fprintf(stderr, "error! user doesn't exist\n");
        return -1;
    }
    char *enc_passwd = crypt(password, pw->sp_pwdp);
    if (strcmp(enc_passwd, pw->sp_pwdp) != 0) {
        char no[] = "Client verify failed";
        SSL_write(ssl, no, static_cast<int>(strlen(no)) + 1);
        fprintf(stderr, "error! password\n");
        return -1;
    }
    char yes[] = "Client verify succeed";
    SSL_write(ssl, yes, static_cast<int>(strlen(yes)) + 1);
    return 0;
}

struct param {
    int client_sock;
    const char *ca_path;
    const char *cert_path;
    const char *key_path;
    int tun_fd;
};

typedef struct {
    char *pipe_file;
    SSL *ssl;
} listen_pipe_param;

void *listen_pipe(void *param) {
    auto ptd = (listen_pipe_param *) param;
    // ./pipe+ptd->pipe_file
    std::string pipe_file_path = "./pipe/";
    std::string pipe_file_name = ptd->pipe_file;
    int pipe_fd = open((pipe_file_path + pipe_file_name).c_str(), O_RDONLY);
    if (pipe_fd < 0) {
        printf("open pipe file %s error\n", (pipe_file_path + pipe_file_name).c_str());
    }
    long len;
    do {
        char buff[BUFFER_SIZE];
        bzero(buff, BUFFER_SIZE);
        len = read(pipe_fd, buff, BUFFER_SIZE);
        SSL_write(ptd->ssl, buff, static_cast<int>(len));
    } while (len >= 0);
    printf("%s read 0 byte. Close connection and remove file.\n", ptd->pipe_file);
    remove(ptd->pipe_file);
    return nullptr;
}

void listen_sock(SSL *ssl, int tun_fd) {
    int len;
    do {
        char buf[BUFFER_SIZE];
        len = SSL_read(ssl, buf, sizeof(buf) - 1);
        long size = write(tun_fd, buf, len);
        if (size < 0) {
            break;
        }
        buf[len] = '\0';
    } while (len > 0);
    printf("SSL shutdown.\n");
}

void *process_connection(void *arg) {
    struct param _param = *(struct param *) arg;

    SSL_CTX *ctx = server_ssl_init(_param.ca_path, _param.cert_path, _param.key_path);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, _param.client_sock);

    int err = SSL_accept(ssl);
    if (err <= 0) {
        err = SSL_get_error(ssl, err);
        fprintf(stderr, "error! SSL_accept return fail error:%d!\n", err);
        perror("Error during SSL_accept");
        ERR_print_errors_fp(stderr);
    }
    fprintf(stdout, "SSL_accept success!\n");

    // verify client
    if (verify(ssl) != 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(_param.client_sock);
        return nullptr;
    }

    // send virtual ip to client
    std::string virtual_ip = allocIPAddr();
    SSL_write(ssl, virtual_ip.c_str(), static_cast<int>(virtual_ip.length()) + 1);
    // virtual_ip 去掉网络范围
    std::string old_virtual_ip = virtual_ip;
    virtual_ip = virtual_ip.substr(0, virtual_ip.find_last_of('/'));

    // start to transfer data
    //select_tun(ssl, _param.client_sock, tun_fd);
    auto lpp = (listen_pipe_param *) malloc(sizeof(listen_pipe_param));
    lpp->ssl = ssl;
    lpp->pipe_file = (char *) malloc(1024);
    strcpy(lpp->pipe_file, virtual_ip.c_str());
    std::string pipe_path = "./pipe/";
    std::string pipe_file = lpp->pipe_file;


    if (mkfifo((pipe_path + pipe_file).c_str(), 0666) == -1) {
        printf("[The IP %s is occupied.Choose another one.]", lpp->pipe_file);
        releaseIPAddr(old_virtual_ip);
        free(lpp);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(_param.client_sock);
        return nullptr;
    }

    pthread_t listen_pipe_thread;
    // remote to client
    pthread_create(&listen_pipe_thread, nullptr, listen_pipe, (void *) lpp);

    // client to remote
    listen_sock(ssl, _param.tun_fd);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(_param.client_sock);
    return nullptr;
}

int VPNServer::setupTunDevice() {
    auto ifr = (struct ifreq *) malloc(sizeof(ifreq));
    memset(ifr, 0, sizeof(ifreq));
    ifr->ifr_flags = IFF_TUN | IFF_NO_PI;
    //IFF_TUN:create a tun device
    //IFF_NO_PI:Do not provide packet information

    //create a tun device
    int tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd == -1) {
        fprintf(stderr, "error! open TUN failed! (%d: %s)\n", errno, strerror(errno));
        free(ifr);
        return -1;
    }

    //register device work-model
    int ret = ioctl(tun_fd, TUNSETIFF, ifr);
    if (ret == -1) {
        fprintf(stderr, "error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        free(ifr);
        return -1;
    }

    //tun id
    int tunId = static_cast<int>(strtol(ifr->ifr_name + 3, nullptr, 10));

    //client_virtual_ip=tunID+127,target_virtual_ip=tunID+1
    char cmd[BUFFER_SIZE];
    snprintf(cmd, BUFFER_SIZE, "ip addr add %s dev tun%d", get_ip_by_cidr(this->virtual_ip_cidr, 1).c_str(), tunId);
    //route config
    int err = system(cmd);
    printf("%s\n", cmd);
    if (err == -1) {
        fprintf(stderr, "error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        free(ifr);
        return -1;
    }

    snprintf(cmd, BUFFER_SIZE, "ip link set tun%d up", tunId);
    err = system(cmd);
    printf("%s\n", cmd);
    if (err == -1) {
        fprintf(stderr, "error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        free(ifr);
        return -1;
    }

    // target -> client route
    snprintf(cmd, BUFFER_SIZE, "ip route add %s dev tun%d", this->virtual_ip_cidr.c_str(), tunId);
    err = system(cmd);
    printf("%s\n", cmd);
    if (err == -1) {
        fprintf(stderr, "error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        free(ifr);
        return -1;
    }

    free(ifr);
    return tun_fd;
}

[[noreturn]] void *listen_tun(void *_tun_fd) {
    int tun_fd = *((int *) _tun_fd);
    char buff[BUFFER_SIZE];
    while (true) {
        long len = read(tun_fd, buff, BUFFER_SIZE);
        if (len > 19 && buff[0] == 0x45) {
            auto ip_header = (struct iphdr *) buff;
            char pipe_file[BUFFER_SIZE];
            snprintf(pipe_file, BUFFER_SIZE, "./pipe/%s", int_to_ip(ntohl(ip_header->daddr)).c_str());
            int fd = open(pipe_file, O_WRONLY);
            if (fd == -1) {
                printf("[WARN] File %s is not exist.\n", pipe_file);
            } else {
                long size = write(fd, buff, len);
                if (size == -1) {
                    printf("[WARN] Write to pipe %s failed.\n", pipe_file);
                }
            }
        }
    }
}

void VPNServer::initIPPool() {
    init_ip_pool(this->virtual_ip_cidr);
}

void VPNServer::cleanPipes() {
    DIR *dir;
    struct dirent *ptr;
    dir = opendir("./pipe");
    while ((ptr = readdir(dir)) != nullptr) {
        if (ptr->d_name[0] == '.')
            continue;
        std::string file_name = ptr->d_name;
        std::string file_path = "./pipe/" + file_name;
        remove(file_path.c_str());
    }
    closedir(dir);
}

[[noreturn]] void VPNServer::Listen() {
    cleanPipes();
    initIPPool();
    int listen_sock = setupTcpServer();

    int tun_fd = setupTunDevice();
    pthread_t listen_tun_thread;
    pthread_create(&listen_tun_thread, nullptr, listen_tun, (void *) &tun_fd);

    while (true) {
        int client_sock = accept_tcp_client(listen_sock);
        if (client_sock == -1) {
            fprintf(stderr, "error! client_sock return fail!\n");
            continue;
        }
        auto client_arg = (struct param *) malloc(sizeof(struct param));
        client_arg->client_sock = client_sock;
        client_arg->ca_path = this->ca_path.c_str();
        client_arg->cert_path = this->cert_path.c_str();
        client_arg->key_path = this->key_path.c_str();
        client_arg->tun_fd = tun_fd;
        pthread_t tid;
        int ret = pthread_create(&tid, nullptr, process_connection, (void *) client_arg);
        if (ret != 0) {
            perror("pthread_create failed");
        }
    }
}
