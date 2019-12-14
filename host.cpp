
// Server side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <time.h>
#include <random>
#include <chrono>

#include "rc4.h"
#include "sha1.h"

#define PORT 1500
#define MAXLINE 1024

using namespace std;

//square and multiply method for fast modular exponentiation
unsigned long long int sqMul(unsigned long long x, unsigned long long H, unsigned long long n) {  
	unsigned long long int h;
	unsigned long long int r;
	int bin[64];
	int i = 0;
	r = x;
	while (H > 0) {  //converting to binary
		if (H % 2 == 0) {
			bin[i] = 0;
		}
		else {
			bin[i] = 1;
		}
		H = H / 2;
		i++;
	}
	i--;
	while (i > 0) {
		r = (r * r) % n;
		i--;
		if (bin[i] == 1) {
			r = (r * x) % n;
		}
	}
	return r;
}

// reads in the diffie hellman parameters
void readParam(unsigned long long int &p, unsigned long long int &q, string &hash) {
	ifstream fin;
	fin.open("param.txt");
	fin >> p >> q >> hash;
	fin.close();
}

//function to get a hash of key concatenated with message
string hashedMsg(string key, string msg) {
	string concMsg = key + msg;
	SHA1 sha_1;
	return sha_1.sha1(concMsg);
}

//function to get rc4 of message concatenated with hash value
string cipherMsg(string key, string msg, string hash) {
	string concMsg = msg + hash;
	return rc4(concMsg, key);
}

//function to sperate message from hash 
string separateMsg(string concMsg, string& h) {
	string rMsg = concMsg;
	istringstream iss(rMsg);
	string msgWithHash;
	iss >> msgWithHash;
	string lenOfMsg;
	iss >> lenOfMsg;
	int lenofMsg = stoi(lenOfMsg);

	string msg = msgWithHash.substr(0, lenofMsg);
	h = msgWithHash.substr(lenofMsg, 100);
	return msg;
}

//function to encrypt message
void encryptMyMsg(string& msgg, string k) {
	msgg = cipherMsg(k, msgg, hashedMsg(k, msgg) + " " + to_string(msgg.length()));
}

//checks if received message is valid and secure
bool checkMsg(string k, string recvMsg, string &finalMsg) {
	string hashValue;
	string msgWithHash = cipherMsg(k, recvMsg, "");
	string realMsg = separateMsg(msgWithHash, hashValue);
	string hashedRealMsg = hashedMsg(k, realMsg);
	finalMsg = realMsg;
	if (hashedRealMsg == hashValue) return true;
	else
		return false;
}

// Driver code
int main() {
    int h_socket;
    char buffer[MAXLINE];
    const char *msg;
    struct sockaddr_in servaddr, cliaddr;
	const string confirmationMessage = "Key Confirmation";

	bool progState = true;

		// Creating socket file descriptor
		if ((h_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			std::cerr << "Socket creation failed." << std::endl;
			exit(EXIT_FAILURE);
		}
		memset(&servaddr, 0, sizeof(servaddr));
		memset(&cliaddr, 0, sizeof(cliaddr));

		// Filling server information
		servaddr.sin_family = AF_INET; // IPv4
		servaddr.sin_addr.s_addr = INADDR_ANY;
		servaddr.sin_port = htons(PORT);

		// Bind the socket with the server address
		if (bind(h_socket, (const struct sockaddr*) & servaddr,
			sizeof(servaddr)) < 0)
		{
			std::cerr << "Binding failed." << std::endl;
			exit(EXIT_FAILURE);
		}

		//reads in params from the file
		unsigned long long int p, g, y, a, clientSecret, k;
		string hash;
		string paramForClient;
		readParam(p, g, hash);
		paramForClient = to_string(p) + " " + to_string(g);
		const char* paramForClientFinal = paramForClient.c_str();
		
		do{
			//wait for initial request from client
			cout << "Listening for requests at port " << PORT << "..." << endl;
			int n;
			socklen_t len = sizeof(cliaddr);
			n = recvfrom(h_socket, (char*)buffer, MAXLINE, 0, (struct sockaddr*) & cliaddr, &len);
			buffer[n] = '\0';

			string req(buffer);

			cout << "Received conn. request from client. Sending DH parameters..." << endl;
			//send params to client Bob
			if (req == "bob") {
				sendto(h_socket, (char*)paramForClientFinal, strlen(paramForClientFinal),
					0, (struct sockaddr*) & cliaddr,
					len);
			}

			cout << "Receiving client's DH secret..." << endl;
			//receive client's encrypted msg
			n = recvfrom(h_socket, (char*)buffer, MAXLINE, 0, (struct sockaddr*) & cliaddr, &len);
			buffer[n] = '\0';

			string enSecret(buffer), clSecret = rc4(enSecret, hash);

			cout << "Calculating an encrypted random DH secret..." << endl;

			// generating random secret x for Bob
			default_random_engine dre(chrono::steady_clock::now().time_since_epoch().count());
			uniform_int_distribution<long long int> dis(0, (int)((p - 1) / 2));
			y = dis(dre);

			//calculating g^x % p using square and multiply method
			a = sqMul(g, y, p);
			string aA = to_string(a);

			string rc4String = rc4(aA, hash);
            const char* rc4msg = rc4String.c_str();

			cout << "Sending secret to client..." << endl;
			//sending Alice's encrypted secret to client
			if (sendto(h_socket, rc4msg, strlen(rc4msg), 0, (struct sockaddr*) & cliaddr, len) < 0) {
				cerr << "Failed." << endl;
				return 0;
			}

			cout << "Calculating the shared key K..." << endl;
			//calculating the shared key
			bool cond = true;
			for (int t = 0; t < clSecret.length(); t++) {
				if (!isdigit(clSecret[t])) {
					cond = false;
					break;
				}
			}

			if (cond == true) {
				clientSecret = stoull(clSecret, nullptr);
				k = sqMul(clientSecret, y, p);
			}
			else
			{
				k = 10;
			}
			cout << "Receiving encrypted key confirmation msg from client..." << endl;
			//waiting for key confirmation message from client
			n = recvfrom(h_socket, (char*)buffer, MAXLINE, 0, (struct sockaddr*) & cliaddr, &len);
			buffer[n] = '\0';

			//decrypting the message
			string receivedConfMsg(buffer);
			string decryptReceivedConfMsg = rc4(receivedConfMsg, to_string(k));

			string acceptMsg = "Handshake successful.";
			const char* acceptMessage = acceptMsg.c_str();

			string refuseMsg = "Handshake unsuccessful. Bye bye.";
			const char* refuseMessage = refuseMsg.c_str();

			if (decryptReceivedConfMsg == confirmationMessage) {

				if (sendto(h_socket, acceptMessage, strlen(acceptMessage), 0, (struct sockaddr*) & cliaddr, len) < 0) {
					cerr << "Failed." << endl;
					return 0;
				}
				cout << "Result: " << acceptMessage << endl;

				for (;;) {
					n = recvfrom(h_socket, (char*)buffer, MAXLINE, MSG_WAITALL, (struct sockaddr*) & cliaddr, &len);
					buffer[n] = '\0';
					string fMsg, exitMsg;
					if (checkMsg(to_string(k), string(buffer), fMsg)) {
						cout << "Client: " << fMsg << endl;
						exitMsg = fMsg;
						if (exitMsg == "exit") return 0;
					}
					std::cout << "Message to client: ";
					std::string msgg, msgG;
					std::cin >> msgg;
					msgG = msgg;
					encryptMyMsg(msgg, to_string(k));
					msg = msgg.c_str();
					sendto(h_socket, (char*)msg, strlen(msg),
						0, (struct sockaddr*) & cliaddr,
						len);
					std::cout << "Msg sent." << std::endl;
					if (msgG == "exit") {
						cout << "Program terminated. " << endl;
						return 0;
					}
				}
			}
			else
			{
				if (sendto(h_socket, refuseMessage, strlen(refuseMessage), 0, (struct sockaddr*) & cliaddr, len) < 0) {
					cerr << "Failed." << endl;
					return 0;
				}
				cout << "Result: " << refuseMessage << endl;
			}
	    }
	    while (progState);

    return 0;
}
