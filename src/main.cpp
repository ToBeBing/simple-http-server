#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <sstream>

std::vector<std::string> StringSplit(std::string s, char split){
   std::istringstream iss(s);
   std::vector<std::string> res;
   std::string token;
   while(getline(iss, token, split)){
      res.push_back(token);
   } 
   return res;
}

void Log(const char* messgae){
  std::cout <<"[Log]: "<< messgae <<std::endl;
}

int main(int argc, char **argv) {
  // Flush after every std::cout / std::cerr
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;
  
  // You can use print statements as follows for debugging, they'll be visible when running tests.
  // std::cout << "Logs from your program will appear here!\n";
  Log("Logs from your program will appear here!");

  // Uncomment this block to pass the first stage
  //
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    std::cerr << "Failed to create server socket\n";
    return 1;
  }
  
  // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    std::cerr << "setsockopt failed\n";
    return 1;
  }
  
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(4221);
  
  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
    std::cerr << "Failed to bind to port 4221\n";
    return 1;
  }
  
  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    std::cerr << "listen failed\n";
    return 1;
  }
  
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof(client_addr);
  
  Log("Waiting for a client to connect...");
  
  while(true){
     int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len); //阻塞函数，程序等待客户端连接
     if(client_fd < 0){
         std::cerr << "accept failed\n";
         continue;
     }
     Log("Client connected");
     std::vector<char> buffer(1024);
     std::string request;
     ssize_t bytes_received = recv(client_fd, buffer.data(), buffer.size(), 0);
     if(bytes_received > 0){
        request.assign(buffer.data(), bytes_received);
        std::cout << request << std::endl;
        // 解析字符串
        // 1. 解析请求行 (e.g., "GET /index.html HTTP/1.1")
        std::stringstream request_stream(request);
        std::string method, path, http_version;
        std::string line;

        if(std::getline(request_stream, line) && !line.empty()){
            std::stringstream request_line_stream(line);
            request_line_stream >> method >> path >> http_version;
        }
        // 2.解析headers
        std::string host;
        std::string accept;
        std::string user_agent;
        while(std::getline(request_stream, line) && !line.empty()){
            std::stringstream request_line_stream(line);
            std::string buff;
            request_line_stream >> buff;
            if(buff == "Host:") request_line_stream >> host;
            else if(buff == "Accept:") request_line_stream >> accept;
            else if(buff == "User-Agent:") request_line_stream >> user_agent;
        }

        std::vector<std::string> v = StringSplit(path, '/');
        // Log(v[1].c_str());
        Log(user_agent.c_str());

        //2 .发送消息
        if (path == "/") {
            // 对于根路径，直接返回 200 OK
            std::string http_response = "HTTP/1.1 200 OK\r\n\r\n";
            send(client_fd, http_response.data(), http_response.size(), 0);
        } 
        // 检查路径是否是 /echo/... 格式
        else if (v.size() > 1 && (v[1] == "echo")) {
            // 确保 v.back() 是安全的
            std::string body = v.back();
            std::string headers = "Content-Type: text/plain\r\nContent-Length: " + std::to_string(body.size()) +"\r\n\r\n";
            std::string status_ok = "HTTP/1.1 200 OK\r\n";
            std::string http_response = status_ok + headers + body;
            send(client_fd, http_response.data(), http_response.size(), 0);
        }
        else if(v.size() > 1 && (v[1] == "user-agent")) {
            std::string body = user_agent;
            std::string headers = "Content-Type: text/plain\r\nContent-Length: " + std::to_string(user_agent.size()) +"\r\n\r\n";
            std::string status_ok = "HTTP/1.1 200 OK\r\n";
            std::string http_response = status_ok + headers + body;
            send(client_fd, http_response.data(), http_response.size(), 0);
        }
        // 其他所有情况，返回 404 Not Found
        else {
            std::string http_response = "HTTP/1.1 404 Not Found\r\n\r\n";
            send(client_fd, http_response.data(), http_response.size(), 0);
        }

     }else if(bytes_received == 0){
        Log("Client disconnected.");
     }

    close(client_fd);
  }
  
  close(server_fd);
  return 0;
}
