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
#include <cerrno>
#include <csignal>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 4096

// 事件处理器结构体
struct Handler {
    std::function<void()> read_cb;
    std::function<void()> write_cb;
    std::string output_buffer;
    std::string input_buffer;
};

class Reactor {
private:
    int epoll_fd;
    std::unordered_map<int, Handler> handlers;

public:
    Reactor() {
        epoll_fd = epoll_create1(0);
        if (epoll_fd == -1) {
            throw std::runtime_error("Failed to create epoll");
        }
    }

    ~Reactor() {
        close(epoll_fd);
    }
	
	Handler& get_handler(int fd) { return handlers[fd]; }

    void register_handler(int fd, uint32_t events, Handler handler) {
        struct epoll_event ev;
        ev.events = events;
        ev.data.fd = fd;
        
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            throw std::runtime_error("Failed to add fd to epoll");
        }
        handlers[fd] = handler;
    }

    void modify_handler(int fd, uint32_t events) {
        struct epoll_event ev;
        ev.events = events;
        ev.data.fd = fd;
        
        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) == -1) {
            throw std::runtime_error("Failed to modify epoll events");
        }
    }

    void remove_handler(int fd) {
        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr) == -1) {
            std::cerr << "Error removing fd from epoll: " << strerror(errno) << std::endl;
        }
        handlers.erase(fd);
        close(fd);
    }

    void run_loop() {
        std::vector<epoll_event> events(MAX_EVENTS);
        
        while (true) {
            int nfds = epoll_wait(epoll_fd, events.data(), MAX_EVENTS, -1);
            if (nfds == -1) {
                throw std::runtime_error("epoll_wait error");
            }

            for (int i = 0; i < nfds; ++i) {
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
                    remove_handler(fd);
                }
            }
        }
    }
};

// 设置非阻塞模式
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    signal(SIGPIPE, SIG_IGN); // 忽略SIGPIPE信号

    try {
        Reactor reactor;
        
        // 创建监听socket
        int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (listen_fd == -1) {
            throw std::runtime_error("Failed to create socket");
        }

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(8080);
		
		int opt = 1;
		setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if (bind(listen_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
            throw std::runtime_error("Bind failed");
        }

        if (listen(listen_fd, SOMAXCONN) == -1) {
            throw std::runtime_error("Listen failed");
        }

        // 注册监听socket的读事件处理
        Handler accept_handler;
        accept_handler.read_cb = [&]() {
            while (true) {
                sockaddr_in client_addr{};
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(listen_fd, (sockaddr*)&client_addr, &client_len);
                
                if (client_fd == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break; // 没有更多连接了
                    } else {
                        std::cerr << "Accept error: " << strerror(errno) << std::endl;
                        break;
                    }
                }

                set_nonblocking(client_fd);
                
                // 注册客户端socket的处理器
                Handler client_handler;
                client_handler.read_cb = [&reactor, client_fd]() {
                    char buffer[BUFFER_SIZE];
                    while (true) {
                        ssize_t n = read(client_fd, buffer, sizeof(buffer));
                        if (n == -1) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                break; // 数据读取完毕
                            } else {
                                reactor.remove_handler(client_fd);
                                return;
                            }
                        } else if (n == 0) {
                            reactor.remove_handler(client_fd);
                            return;
                        } else {
                            // 处理接收到的数据（示例：回显）
                            reactor.get_handler(cfd).output_buffer.append(buffer, n);
                            reactor.modify_handler(client_fd, EPOLLIN | EPOLLOUT | EPOLLET);
                        }
                    }
                };

                client_handler.write_cb = [&reactor, client_fd]() {
                    auto& buffer=reactor.get_handler(cfd).output_buffer;
                    if (output_buffer.empty()) {
                        reactor.modify_handler(client_fd, EPOLLIN | EPOLLET);
                        return;
                    }

                    ssize_t n = write(client_fd, output_buffer.data(), output_buffer.size());
                    if (n == -1) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            reactor.remove_handler(client_fd);
                        }
                        return;
                    }

                    output_buffer.erase(0, n);
                    if (output_buffer.empty()) {
                        reactor.modify_handler(client_fd, EPOLLIN | EPOLLET);
                    }
                };

                reactor.register_handler(client_fd, EPOLLIN | EPOLLET, client_handler);
            }
        };

        reactor.register_handler(listen_fd, EPOLLIN | EPOLLET, accept_handler);
        reactor.run_loop();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
