#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>          
#include <stdio.h>	
#include <string>	
#include <cstring>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <sstream>
#include <time.h>
#include <random>
#include <chrono>

#include "sha1.h"
#include "rc4.h"

#define PORT     1500
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

//Hashing concatenations of key and message
string hashedMsg(string key, string msg) {
	string concMsg = key + msg;
	SHA1 sha_1;
	return sha_1.sha1(concMsg);
}

//RC4 of message+hash
string cipherMsg(string key, string msg, string hash) {
	string concMsg = msg + hash;
	return rc4(concMsg, key);
}

//separating message from hash
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

//encrypting the message and adding a pointer(length of message) at the end to help decryption
void encryptMyMsg(string &msgg, string k) {
	msgg = cipherMsg(k, msgg, hashedMsg(k, msgg) + " " + to_string(msgg.length()));
}

//function to check if the message is valid and secure
bool checkMsg(string k, string recvMsg, string& finalMsg) {
	string hashValue;
	string msgWithHash = cipherMsg(k, recvMsg, "");
	string realMsg = separateMsg(msgWithHash, hashValue);
	string hashedRealMsg = hashedMsg(k, realMsg);
	finalMsg = realMsg;
	if (hashedRealMsg == hashValue) return true;
	else
		return false;
}

int main(){
  int cl_socket;
  char buffer[MAXLINE], params[MAXLINE];
  const char* msg;
  const char* servAd = "127.0.0.1";
  struct hostent *hp;     /* host information */
  struct sockaddr_in servaddr;    /* server address */
  const string confirmationMsg = "Key Confirmation";
  const char* successHandshake = "Handshake successful.";
  unsigned long long int p, g, x, b, hostSecret, k;
  string pw, hash;


  if ((cl_socket = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    std::cerr << "cannot create socket";
    return 0;
  }

  /* fill in the server's address and data */
  memset((char*)&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(1500);     // Assign port in network byte order
  servaddr.sin_addr.s_addr = INADDR_ANY;
  
  bool pwValidation = true;
  while (pwValidation) {
	  cout << "Enter password: ";
	  cin >> pw;
	  if (pw.length() >= 6) pwValidation = false;
	  for (int it = 0; it < pw.length(); it++) {
		  if (!isalnum(pw[it])) pwValidation = true;
	  }
  }

  //calculating SHA-1 of the password
  SHA1 s;
  hash = s.sha1(pw);

  int n;
  socklen_t len;

  //sending initial request to host
  cout << "Sending connection request..." << endl;
  string conn_r = "bob";
  const char* conn_req = conn_r.c_str();

  if (sendto(cl_socket, conn_req, strlen(conn_req), 0, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
	  cerr << "Failed." << endl;
	  return 0;
  }

  cout << "Receiving DH parameters..." << endl;
  //receive DH parameters from host
  n = recvfrom(cl_socket, (char*)params, MAXLINE,
	  MSG_WAITALL, (struct sockaddr*) & servaddr,
	  &len);

  string paramsString(params);
  istringstream iss (paramsString);
  string stream;
  iss >> stream;
  p = stoull(stream, nullptr);
  iss >> stream;
  g = stoull(stream, nullptr);

  // generating random secret x for Bob
  cout << "Calculating random secret..." << endl;
  default_random_engine dre(chrono::steady_clock::now().time_since_epoch().count());
  uniform_int_distribution<long long int> dis(0, (int)((p - 1) / 2));
  x = dis(dre);

  //calculating g^x % p using square and multiply method
  b = sqMul(g,x,p);
  string bB = to_string(b), rc4String = rc4(bB, hash);
  const char* rc4msg = rc4String.c_str();

  //sending Bob's encrypted secret to host
  cout << "Sending encrypted secret to host..." << endl;
  if (sendto(cl_socket, rc4msg, strlen(rc4msg), 0, (struct sockaddr*) & servaddr, sizeof(servaddr)) < 0) {
	  cerr << "Failed." << endl;
	  return 0;
  }

  //receive host's encrypted msg
  cout << "Receiving encrypted secret from host..." << endl;
  n = recvfrom(cl_socket, (char*)buffer, MAXLINE, 0, (struct sockaddr*) & servaddr, &len);
  buffer[n] = '\0';

  string enSecret(buffer);

  string hSecret = rc4(enSecret, hash);

  //calculating shared secret K
  cout << "Calculating shared secret K..." << endl;
  bool cond = true;
  for (int t = 0; t < hSecret.length(); t++) {
	  if (!isdigit(hSecret[t]))  cond = false;
  }

  if (cond) {
	  hostSecret = stoull(hSecret, nullptr);
	  k = sqMul(hostSecret, x, p);
  }
  else {
	  k = 100;
  }

  cout << "Encrypting confirmation message with K and sending to host..." << endl;

  string encryptedCMsg = rc4(confirmationMsg, to_string(k));
  const char* encryptedConfirmMsg = encryptedCMsg.c_str();

  //sending key confirmation message encrypted with shared key to host
  if (sendto(cl_socket, encryptedConfirmMsg, strlen(encryptedConfirmMsg), 0, (struct sockaddr*) & servaddr, sizeof(servaddr)) < 0) {
	  cerr << "Failed." << endl;
	  return 0;
  }

  char handresult[MAXLINE];
  //receive handshake result
  cout << "Handshake result received... " << endl;
  n = recvfrom(cl_socket, (char*)handresult, MAXLINE, 0, (struct sockaddr*) & servaddr, &len);
  handresult[n] = '\0';

  cout << "handshake result: " << handresult << endl;

  const string conf(buffer);

  if (strcmp(handresult, successHandshake)) {
	  return 0;
  }

  for (;;){
    /* send a message to the host */
    std::cout << "Message to host: ";
    std::string msgg, msgG;
	cin >> msgg;
	msgG = msgg;
	encryptMyMsg(msgg, to_string(k));
    msg = msgg.c_str();
    if (sendto(cl_socket, (char*)msg, strlen(msg), 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
	  cerr << "Failed." << endl;
      return 0;
    } 
	if (msgG == "exit") {
		cout << "program terminated." << endl;
		return 0;
	}

    /* receive msg from host */
    n = recvfrom(cl_socket, (char *)buffer, MAXLINE,
                  MSG_WAITALL, (struct sockaddr *) &servaddr,
                  &len);
      buffer[n] = '\0';
	  string fMsg, exitMsg;
	  if (checkMsg(to_string(k), string(buffer), fMsg)) {
		  cout << "Host: " << fMsg << endl;
		  exitMsg = fMsg;
	      if (exitMsg == "exit") return 0;
	  }
	  else {
		  cout << "Unable to receive message." << endl;
	  }
  }

}
