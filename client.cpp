// client
// Jason Clark 800617442

#include <iostream>
#include <fstream>
#include <math.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define DEBUGGING 0 // 0 false 1 true
#define MAXDATASIZE 1000

using namespace std;

void smtp_client(char* server_ip, char* smtp_port);
void http_client(char* server_ip, char* http_port);
void read_config(char *argv[], char* server_ip, char* smtp_port, char* http_port);
void *get_in_addr(struct sockaddr *sa);
string data_helper();
string encode_password(string password);
string decode_password(string password_64);


int main(int argc, char *argv[])
{
    char smtp_port[6]; 
    char http_port[6];
    char server_ip[INET_ADDRSTRLEN];
    char client_type[20];

    if(argc != 2)
    {
        perror("Error, only one runtime argument accepted: client.conf");
        return 0;
    }
    else
    {
        read_config(argv, server_ip, smtp_port, http_port);
    }

    cout << "Please enter type of client: (http, smtp)\n>";
    cin.getline(client_type, 20);
    if(client_type[0] == 'h' && client_type[1] == 't' && client_type[2] == 't' && client_type[3] == 'p')
    {
        http_client(server_ip, http_port);
    }
    else if (client_type[0] == 's' && client_type[1] == 'm' && client_type[2] == 't' && client_type[3] == 'p')
    {
        smtp_client(server_ip, smtp_port);
    }
    else
    {
        cout << "invalid client type\n";
    }

    cout << "\nClient has finished execution...\n";
    return 0;
    
}

void smtp_client(char* server_ip, char* smtp_port)
{
    int sockfd, numbytes;  
    char in_buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(server_ip, smtp_port, &hints, &servinfo)) != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) 
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) 
        {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) 
        {
            close(sockfd);
            perror("client: connect");
            continue;
        }
        break;
    }
    
    if (p == NULL) 
    {
        fprintf(stderr, "client: failed to connect\n");
        return;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    printf("client: connecting to %s port %s\n", s, smtp_port);

    string user_input;
    char out_buf[MAXDATASIZE];

    while(true) // -----------------------------------------------------------------------------------------
    {

        if((out_buf[0]=='D'&&out_buf[1]=='A'&&out_buf[2]=='T'&&out_buf[3]=='A')&&(in_buf[0]=='3'&&in_buf[1]=='5'&&in_buf[2]=='4'))
        {
            string email = data_helper();
            strcpy(out_buf, email.c_str());
        }
        else if(in_buf[0]=='3'&&in_buf[1]=='3'&&in_buf[2]=='4'&&in_buf[3]==' ' &&in_buf[4]=='c')
        {
            cout << ">";
            cin.getline(out_buf, MAXDATASIZE);
            string s_out(out_buf);
            s_out = encode_password(s_out);
            strcpy(out_buf, s_out.c_str());
        }
        else
        {
            cout << ">";
            cin.getline(out_buf, MAXDATASIZE);
        }
        
        if(send(sockfd, out_buf, sizeof out_buf, 0 ) == -1)
        {
            perror("send");
        }
        if ((numbytes = recv(sockfd, in_buf, MAXDATASIZE-1, 0)) == -1) 
        {
            perror("recv");
            exit(1);
        }
        in_buf[numbytes] = '\0';


        // if(in_buf[0]=='3'&&in_buf[1]=='3'&&in_buf[2]=='4')
        // {
        //     // decode server message and print
        //     string tmp(in_buf);
        //     tmp.erase(0,4);
        //     tmp.pop_back();
        //     tmp = decode_password(tmp);
        //     tmp = "334 " + tmp;
        //     strcpy(in_buf, tmp.c_str());
        //     printf("<%s\n",in_buf);
        //     continue;
        // }

        if(in_buf[0]=='3'&&in_buf[1]=='3'&&in_buf[2]=='0')
        {
            string tmp(in_buf);
            tmp.erase(0,4);
            tmp.pop_back();
            
            tmp = decode_password(tmp);
            tmp = "330 " + tmp;
            
            strcpy(in_buf, tmp.c_str());
            printf("<%s\n",in_buf);
            cout << "attempting disconnect reconnect\n";
            sleep(5);
            close(sockfd);

            for(p = servinfo; p != NULL; p = p->ai_next) 
            {
                if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) 
                {
                    perror("client: socket");
                    continue;
                }

                if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) 
                {
                    close(sockfd);
                    perror("client: connect");
                    continue;
                }
                break;
            }

            if (p == NULL) 
            {
                fprintf(stderr, "client: failed to connect\n");
                return;
            }
            continue;
        }



        printf("<%s\n",in_buf);
        if((out_buf[0]=='Q'&&out_buf[1]=='U'&&out_buf[2]=='I'&&out_buf[3]=='T')&&(in_buf[0]=='2'&&in_buf[1]=='2'&&in_buf[2]=='1'))
        {
            break;
        }
    }

    close(sockfd);
    return;
}

void http_client(char* server_ip, char* http_port)
{
    int sockfd, numbytes;  
    char in_buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    printf("sip: %s\n", server_ip);
    printf("http_port: %s\n", http_port);
    
    if ((rv = getaddrinfo(server_ip, http_port, &hints, &servinfo)) != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) 
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) 
        {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) 
        {
            close(sockfd);
            perror("client: connect");
            continue;
        }
        break;
    }
    
    if (p == NULL) 
    {
        fprintf(stderr, "client: failed to connect\n");
        return;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    printf("client: connecting to %s\n", s);

    char out_buf[MAXDATASIZE];
    char username[MAXDATASIZE];
    char num_files[MAXDATASIZE];
    char user_input[10];
    string request;

    while(true)
    {
        cout << "Enter username:\n";
        cout << ">";
        cin.getline(username, MAXDATASIZE);
        cout << "Enter number of emails to be retrieved\n";
        cout << ">";
        cin.getline(num_files, MAXDATASIZE);

        request = "";
        request += "GET/db/";
        request += username;
        request += "/ HTTP/1.1\nHost: <";
        request += server_ip;
        request += ">\nCount: ";
        request += num_files;

        strcpy(out_buf, request.c_str());
        
        if(send(sockfd, out_buf, sizeof out_buf, 0 ) == -1)
        {
            perror("send");
        }


        if ((numbytes = recv(sockfd, in_buf, MAXDATASIZE-1, 0)) == -1) 
        {
            perror("recv");
            exit(1);
        }

        in_buf[numbytes] = '\0';

        printf("<%s\n",in_buf);
        cout << "\nWould you like to request more emails? (y/n)\n>";
        cin.getline(user_input, MAXDATASIZE);
        if(user_input[0] == 'n')
            break;
            
    }
    close(sockfd);

    return;
}

void read_config(char *argv[], char* server_ip, char* smtp_port, char* http_port)
{
    int count = 0;
    ifstream config;
    string line;
    string delimiter = "=";
    string args[3];
    size_t position;
    
    config.open(argv[1]);
    
    // erase the content from beginning of string to delim, including delim
    while(getline(config, line))    
    {
        position = line.find(delimiter); 
        line.erase(0, position+delimiter.length());
        args[count] = line;
        count++;
        if(count == 3)
            break;
    }
    config.close();

    strcpy(server_ip, args[0].c_str());
    strcpy(smtp_port, args[1].c_str());
    strcpy(http_port, args[2].c_str());

    return;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

string data_helper()
{
    char out_buf[MAXDATASIZE];
    string message = "";

    bool blocking = true;
    message+="Subject:   ";
    cout << message;
    while(blocking)
    {
        cin.getline(out_buf, MAXDATASIZE);
        if(out_buf[0] == '.')
        {
            blocking = false;
            continue;
        }
        message+=out_buf;
        message+="\n";  
    }
    return message;
}

string encode_password(string password)
{
    BIO *mem ,*b64; 
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_write(b64, password.c_str(), password.length());
    BIO_flush(b64);
    char* data;
    long len = BIO_get_mem_data(mem, &data);
    string res(data, len);
    return res;
}

string decode_password(string password_64)
{
    password_64 += "\n";
    BIO *bmem, *b64;
    char *buf = (char *)malloc(password_64.length());
    memset(buf, 0, password_64.length());
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(password_64.c_str(), password_64.length());
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buf, password_64.length());
    string res(buf);
    return res;
}
