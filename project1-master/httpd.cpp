#include <iostream>
#include "httpd.h"
#include<sys/types.h>
#include<sys/socket.h>
#include<stdio.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<ctype.h>
#include<string.h>
#include<fstream>
#include<vector>
#include<algorithm>
#define SERVER_PORT 8080
using namespace std;

void sendError(int s, string doc_root, int error) {
    char buf[128], path[128];
    strcpy(buf, doc_root.c_str());
    string relative = "/"+to_string(error)+".html";
    strcpy(path, relative.c_str());
    char* abs_path = strcat(buf, path);
    printf("\nabsolute path: %s\n", abs_path);
	FILE *pfile = fopen(abs_path, "r");
	if (pfile == NULL){
		printf("打开%d.html失败\n", error);
		return;
	}
	char temp[1024] = "";
	do{
		fgets(temp, 1024, pfile);
		send(s, temp, strlen(temp), 0);
	} while (!feof(pfile));
}

void sendInfo(int s, char* filename, string doc_root) {
    char buf[128];
    if(strcmp(filename, "/")==0 || strcmp(filename, "")==0)
        strcpy(filename, "/test.html");
    strcpy(buf, doc_root.c_str());
    char* abs_path = strcat(buf, filename);
    printf("\nabsolute path: %s\n", abs_path);
	FILE *pfile = fopen(abs_path, "r");
	if (pfile == NULL){
		printf("打开文件失败\n");
        sendError(s, doc_root, 404);
		return;
	}
	char temp[1024] = "";
	do{
		fgets(temp, 1024, pfile);
		send(s, temp, strlen(temp), 0);
	} while (!feof(pfile));
    printf("send success!\n");
	/*ifstream myfile(filename);
	if(!myfile.is_open()){
		printf("打开文件失败\n");
		return;
	}
	string temp;
	while(getline(myfile, temp)){
		write(s, temp, strlen(temp));
	}*/
}

void get_relative_path(char* name, char* buf ) {
    int j=0, flag=0;
	int len = strlen(name);
    for(int i=0;i<len;i++){
        if(name[i] !=' ' && flag)
            buf[j++]=name[i];
        else if(name[i] ==' ' && !flag)
            flag=1;
        else if(name[i] ==' ' && flag){
            buf[j]='\0';
            break;
        }
    }
}

void get_permit_ip(string filename, vector<string> &allow, vector<string> &deny) {
    ifstream myfile(filename);
	if(!myfile.is_open()){
		printf("打开.htaccess文件失败\n");
		return;
	}
	string temp;
	while(getline(myfile, temp)){
        cout<<"permit infomation: "<<temp<<endl;
        string ip="";
        int flag=0;
        for(int i=0;i<temp.length()-1;i++){ // last character is \n,
            if(' ' == temp[i])
                flag++;
            else if(flag==2 && temp[i] !=' '){
                ip += temp[i];
            }
        }
        if(temp[0] == 'a')
            allow.push_back(ip);
        else
            deny.push_back(ip);
	}
}

int count_max(int base, int ip_num){
    int sum=1;
    for(int i=0;i<8-ip_num;i++)
        sum=sum*2;
    return base+sum-1;
}

bool judge_range(string ip, string source) {
    int ip_array[4], source_array[5]; // string to int
    int i=0,j=0,temp=0;
    while(i<ip.length()){
        if(ip[i] != '.'){
            temp = temp*10 + (ip[i]-'0');
        }else{
            ip_array[j++]=temp;
            temp=0;
        }
        i++;
    }
    ip_array[j]=temp;
    i=j=temp=0;
    while(i<source.length()){
        if(source[i] != '.' && source[i] != '/'){
            temp = temp*10 + (source[i]-'0');
        }else{
            source_array[j++]=temp;
            temp=0;
        }
        i++;
    }
    source_array[j]=temp;
    int flag=source_array[4]/8;
    for(int k=0;k<flag;k++){ // 判断ip前缀是否相同
        if(ip_array[k]!=source_array[k])
            return false;
    }
    if(flag==4)
        return true;
    int max = count_max(source_array[flag], source_array[4]%8);
    cout<<"ip: "<<ip<<endl<<"ip_array: ";
    for(int k=0;k<4;k++){
        if(k==0)
            cout<<ip_array[k];
        else
            cout<<"."<<ip_array[k];
    }
    cout<<"\nsource: "<<source<<endl<<"source_array: ";
    for(int k=0;k<5;k++){
        if(k==0)
            cout<<source_array[k];
        else
            cout<<"."<<source_array[k];
    }
    cout<<"max source: ";
    for(int k=0;k<3;k++){
        if(k==0)
            cout<<source_array[k];
        else
            cout<<"."<<source_array[k];
    }
    cout<<"."<<max<<endl;
    
    if(ip_array[flag]>=source_array[flag] && ip_array[flag]<=max)
        return true;
    else
        return false;
}

bool check_permit(string ip, vector<string> allow, vector<string> deny){
    /*vector<string>::iterator result = find(deny.begin(), deny.end(), ip); //查找deny ip
    vector<string>::iterator result2 = find(allow.begin(), allow.end(), ip); //查找allow ip
    if (result == deny.end()) //没找到
    {
        if (result2 == deny.end()) //没找到
            return false;
        else //找到
            return true;
    }
    else //找到
        return false;*/
    for(int i=0;i<allow.size();i++){
        if(judge_range(ip, allow[i])){
            return true;
        }
    }
    for(int i=0;i<deny.size();i++){
        if(judge_range(ip, deny[i])){
            return false;
        }
    }
    return false;
}

void start_httpd(unsigned short port, string doc_root)
{
    vector<string> allow, deny;
    get_permit_ip(doc_root + "/htdocs/.htaccess", allow, deny);

	cerr << "Starting server (port: " << port <<
		", doc_root: " << doc_root << ")" << endl;
	
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){
        perror("socket create error");
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int isok = bind(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr));
    if(isok == -1){
        perror("socket bind error");
    }

    isok = listen(sockfd, 128);
    if(isok == -1){
        perror("listen error");
    }

    struct sockaddr_in client_addr;
    socklen_t client_addr_len=sizeof(client_addr);
    char filename[BUFSIZ], client_ip[BUFSIZ], info[BUFSIZ];

    while(1){// wait client connect,then read infomation from client
        int clientfd = accept(sockfd, (struct sockaddr*) &client_addr, &client_addr_len);
        if(clientfd == -1){
            perror("client create error");
        }
        
        printf("Client IP:%s, Client port:%d\n", inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, 
            client_ip, sizeof(client_ip)), ntohs(client_addr.sin_port));
        recv(clientfd, info, sizeof(info), 0);
        printf("%s\n has %d bit data.", info, (int)strlen(info));

        get_relative_path(info, filename);
        printf("\nrelative path: %s\n", filename);

        bool permit = check_permit(inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, 
            client_ip, sizeof(client_ip)), allow, deny);
        if(permit)
            //char *filename = (char *)"./test.html";
            sendInfo(clientfd, filename, doc_root);
        else
            sendError(clientfd, doc_root, 403);

        close(clientfd);
    }
    
    close(sockfd);
}
