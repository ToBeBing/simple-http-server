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
#include<thread>
#include<fstream>

std::vector<std::string> StringSplit(std::string s, char split){
   std::istringstream iss(s);
   std::vector<std::string> res;
   std::string token;
   while(getline(iss, token, split)){
      res.push_back(token);
   } 
   return res;
}

void LogError(const char* message){
  std::cout <<"[Error]: "<< message << "\n";
}

std::string readFileContents(const std::string& filepath, bool& open_success){
  std::ifstream fileStream(filepath);
  if(!fileStream.is_open()){
     LogError("open file error");
     open_success = false;
     return "";
  }

  std::stringstream buffer;
  buffer << fileStream.rdbuf();
  return buffer.str();
}

void Log(const char* messgae){
  std::cout <<"[Log]: "<< messgae << "\n";
}


struct http_request{
    std::string method, path, http_version;
    std::string host;
    std::string accept;
    std::string user_agent;

};

struct http_response{
    std::string body;
    std::string http_version;
    std::string content_len;
    std::string content_type;
    std::string status_code;
    std::string status_message;

    std::string response_string(){
        std::string response = http_version + " " + status_code + " " + status_message + "\r\n";
        if(content_len != "" && content_type != ""){
            response += "Content-Length: " + content_len + "\r\n";
            response += "Content-Type: " + content_type + "\r\n";            
        }
        response += "\r\n";
        if(body != ""){
              response += body;
        }
        return response;
    }

    http_response(
    std::string body = "",
    std::string http_version = "HTTP/1.1",
    std::string content_len = "",
    std::string content_type = "",
    std::string status_code="200",
    std::string status_message="Ok"){
        this->body = body;
        this->http_version = http_version;
        this->content_len = content_len;
        this->content_type = content_type;
        this->status_code = status_code;
        this->status_message = status_message;
    }
};

void handle_client(int client_fd, std::string directory){
  Log("Client connected");
  http_request http_request;
     std::vector<char> buffer(1024);
     std::string request;
     ssize_t bytes_received = recv(client_fd, buffer.data(), buffer.size(), 0);
     if(bytes_received > 0){
        request.assign(buffer.data(), bytes_received);
        std::cout << request << std::endl;
        // 解析字符串
        // 1. 解析请求行 (e.g., "GET /index.html HTTP/1.1")
        std::stringstream request_stream(request);
        std::string line;
        if(std::getline(request_stream, line) && !line.empty()){
            std::stringstream request_line_stream(line);
            request_line_stream >> http_request.method >> http_request.path >> http_request.http_version;
        }
        // 2.解析headers
        while(std::getline(request_stream, line) && !line.empty()){
            std::string buff;
            std::stringstream request_line_stream(line);
            request_line_stream >> buff;
            if(buff == "Host:") request_line_stream >> http_request.host;
            else if(buff == "Accept:") request_line_stream >> http_request.accept;
            else if(buff == "User-Agent:") request_line_stream >> http_request.user_agent;
        }

        std::vector<std::string> v = StringSplit(http_request.path, '/');
        // Log(v[1].c_str());
        // Log(http_request.user_agent.c_str());
        // Log(http_request.method.c_str());

        //2 .发送消息
        if (http_request.path == "/") {
            http_response response;
            send(client_fd, response.response_string().data(), response.response_string().size(), 0);
        } 
        // 检查路径是否是 /echo/... 格式
        else if (v.size() > 1 && (v[1] == "echo")) {
            // 确保 v.back() 是安全的
            http_response response(
                 v.back(),
                "HTTP/1.1",
                std::to_string(v.back().size()),
                "text/plain",
                "200",
                "OK"
            );
            send(client_fd, response.response_string().data(), response.response_string().size(), 0);
        }
        else if(v.size() > 1 && (v[1] == "user-agent")) {
            http_response response(
                 http_request.user_agent,
                "HTTP/1.1",
                std::to_string(http_request.user_agent.size()),
                "text/plain",
                "200",
                "OK"
            );
            send(client_fd, response.response_string().data(), response.response_string().size(), 0);
        }
        else if(v.size() > 1 && (v[1] == "files")){
            std::string filename = v[2];
            std::string path = directory +"/"+ filename;
            bool open_success = true;
            std::string content = readFileContents(path, open_success);
            if(!open_success){
                http_response response(
                 "",
                "HTTP/1.1",
                "",
                "",
                "404", 
                "Not Found"
                );
                send(client_fd, response.response_string().data(), response.response_string().size(), 0);
            }
            else{
              http_response response(
                 content,
                "HTTP/1.1",
                std::to_string(content.size()),
                "application/octet-stream",
                "200",
                "OK"
              );
              send(client_fd, response.response_string().data(), response.response_string().size(), 0);
            }
        }
        // 其他所有情况，返回 404 Not Found
        else {
            http_response response(
                 "",
                "HTTP/1.1",
                "",
                "",
                "404", 
                "Not Found"
            );
            send(client_fd, response.response_string().data(), response.response_string().size(), 0);
        }

     }else if(bytes_received == 0){
        Log("Client disconnected.");
     }

    close(client_fd);
}

int main(int argc, char **argv) {
  // Flush after every std::cout / std::cerr
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;

  std::string directory = ".";
  if(argc > 2){
     if (std::string(argv[1]) == "--directory") {
      directory = argv[2];
      Log(("Serving files from directory: " + directory).c_str());
    }
  }
  
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
     std::thread(handle_client,client_fd,directory).detach();
  }
  
  close(server_fd);
  return 0;
}
