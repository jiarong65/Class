#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <functional>
#include <unordered_map>
#include <vector>
#include <string>
#include <iostream>
#include <cstring>
#include <algorithm>
#include<iostream>
#include <cerrno>
#include <csignal>
#include <set>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 4096

struct Handler {
    std::function<void()> read_cb;
    std::function<void()> write_cb;
    std::string input_buffer;
    std::string output_buffer;
    std::string username;  // 新增：存储用户名
};

class Reactor {
private:
    int epfd;
    std::unordered_map<int, Handler> handlers;
    std::set<int> client_fds;  // 存储所有客户端文件描述符

public:
    Reactor() {
        epfd = epoll_create1(0);
        if (epfd == -1) {
            throw std::runtime_error("failed to create epoll");
        }
    }

    ~Reactor() {
        close(epfd);
    }

    Handler& get_handler(int fd) { return handlers[fd]; }

    void register_handler(int fd, uint32_t events, Handler handler) {
        struct epoll_event ev;
        ev.data.fd = fd;
        ev.events = events;

        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            throw std::runtime_error("failed to add fd to epoll");
        }
        handlers[fd] = handler;
        if (fd != 0) {  // 0是标准输入，不加入客户端集合
            client_fds.insert(fd);
        }
    }

    void modify_handler(int fd, uint32_t events) {
        struct epoll_event ev;
        ev.data.fd = fd;
        ev.events = events;

        if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev)) {
            throw std::runtime_error("failed to modify epoll events");
        }
    }

    void remove_handler(int fd) {
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr) == -1) {
            std::cerr << "error removing fd from epoll:" << strerror(errno) << std::endl;
        }
        handlers.erase(fd);
        client_fds.erase(fd);
        close(fd);
    }

    // 广播消息给所有客户端
    void broadcast(const std::string& message, int exclude_fd = -1) {
        for (int fd : client_fds) {
            if (fd != exclude_fd) {
                handlers[fd].output_buffer += message;
                modify_handler(fd, EPOLLIN | EPOLLOUT | EPOLLET);
            }
        }
    }

    void run_loop() {
        std::vector<epoll_event> events(MAX_EVENTS);

        while (true) {
            int nfds = epoll_wait(epfd, events.data(), MAX_EVENTS, -1);
            if (nfds == -1) {
                throw std::runtime_error("epoll_wait error");
            }

            for (int i = 0; i < nfds; i++) {
                int fd = events[i].data.fd;
                auto& handler = handlers[fd];

                if (events[i].events & EPOLLIN) {
                    if (handler.read_cb) {
                        handler.read_cb();
                    }
                }

                if (events[i].events & EPOLLOUT) {
                    if (handler.write_cb) {
                        handler.write_cb();
                    }
                }

                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    if (client_fds.count(fd)) {
                        std::string msg = handler.username + " 离开了聊天室\n";
                        broadcast(msg);
                    }
                    remove_handler(fd);
                }
            }
        }
    }
};

void set_nonblocking(int fd) {
    int flag = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}

int main() {
    signal(SIGPIPE, SIG_IGN); // 忽略SIGPIPE信号

    try {
        Reactor reactor;

        // 创建监听socket
        int lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (lfd == -1) {
            throw std::runtime_error("failed to create socket");
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(8080);

        int opt = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if (bind(lfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
            throw std::runtime_error("bind error");
        }

        if (listen(lfd, SOMAXCONN) == -1) {
            throw std::runtime_error("listen failed");
        }

        // 注册socket读事件处理
        Handler accept_handler;
        accept_handler.read_cb = [&]() {
            while (true) {
                sockaddr_in client_addr{};
                socklen_t client_len = sizeof(client_addr);
                int cfd = accept(lfd, (sockaddr*)&client_addr, &client_len);

                if (cfd == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break; // 没有更多连接
                    } else {
                        std::cerr << "accept error:" << strerror(errno) << std::endl;
                    }
                }

                set_nonblocking(cfd);

                // 注册客户端socket处理器
                Handler client_handler;
                client_handler.username = "用户" + std::to_string(cfd);  // 默认用户名

                // 发送欢迎消息
                std::string welcome_msg = "欢迎来到聊天室! 请输入你的用户名:\n";
                write(cfd, welcome_msg.c_str(), welcome_msg.size());

                client_handler.read_cb = [&reactor, cfd]() {
                    char buffer[BUFFER_SIZE];
                    while (true) {
                        ssize_t n = read(cfd, buffer, BUFFER_SIZE);
                        if (n == -1) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                break;
                            } else {
                                std::string msg = reactor.get_handler(cfd).username + " 异常断开连接\n";
                                reactor.broadcast(msg);
                                reactor.remove_handler(cfd);
                                return;
                            }
                        } else if (n == 0) {
                            std::string msg = reactor.get_handler(cfd).username + " 离开了聊天室\n";
                            reactor.broadcast(msg);
                            reactor.remove_handler(cfd);
                            return;
                        } else {
                            buffer[n] = '\0';  // 确保字符串终止
                            std::string input(buffer);

                            // 处理用户名设置
                            if (reactor.get_handler(cfd).username.find("用户") == 0) {
                                // 去掉可能的换行符
								// 使用 std::remove 移除 '\n' 和 '\r'
    							auto new_end = std::remove(input.begin(), input.end(), '\n');
    							new_end = std::remove(input.begin(), new_end, '\r');

                                if (!input.empty()) {
                                    reactor.get_handler(cfd).username = input;
                                    std::string msg = input + " 加入了聊天室\n";
                                    reactor.broadcast(msg);
                                }
                            } else {
                                // 正常聊天消息
                                std::string msg = reactor.get_handler(cfd).username + ": " + input;
                                reactor.broadcast(msg, cfd);  // 不发送给自己
                            }
                        }
                    }
                };

                client_handler.write_cb = [&reactor, cfd]() {
                    auto& buffer = reactor.get_handler(cfd).output_buffer;
                    if (buffer.empty()) {
                        reactor.modify_handler(cfd, EPOLLIN | EPOLLET);
                        return;
                    }

                    ssize_t n = write(cfd, buffer.data(), buffer.size());
                    if (n == -1) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            reactor.remove_handler(cfd);
                        }
                        return;
                    }

                    buffer.erase(0, n);
                    if (buffer.empty()) {
                        reactor.modify_handler(cfd, EPOLLIN | EPOLLET);
                    }
                };

                reactor.register_handler(cfd, EPOLLIN | EPOLLET, client_handler);
            }
        };

        reactor.register_handler(lfd, EPOLLIN | EPOLLET, accept_handler);
        std::cout << "服务器已启动，监听端口 8080..." << std::endl;
        reactor.run_loop();
    } catch (const std::exception& e) {
        std::cerr << "error:" << e.what() << std::endl;
        return 1;
    }
    return 0;
}
