#include <iostream>
#include <istream>
#include <fstream>
#include <math.h>
#include <cmath>
#include <stdlib.h>
#include <time.h>
#include <string>
#include <random>
#include <chrono>
#include <cctype>
#include <bitset>

#include "sha1.h"

using namespace std;

string getBinary(int l) {   //generates random binary number of given bit length
	int len = l;
	string newBin;
	default_random_engine dre(chrono::steady_clock::now().time_since_epoch().count());
	uniform_int_distribution<int> dis(0, 1);
	newBin.append("1");
	for (int i = 1; i < len - 1; i++) {
		int j = dis(dre);
		string cj = to_string(j);
		newBin.append(cj);
	}
	newBin.append("1");
	return newBin;

}

unsigned long long int binToDeci(string bin) {   //transforms binary to decimal
	string num = bin;
	unsigned long long int decValue = 0;
	unsigned long long int base = 1;
	unsigned long long int len = num.length();
	for (int i = len - 1; i >= 0; i--) {
		if (num[i] == '1')
			decValue += base;
		base = base * 2;
	}
	return decValue;
	/*unsigned long long decValue = std::bitset<32>(bin).to_ullong();
	return decValue;*/
}

bool checkPrime(unsigned long long int p) {   //checks if decimal number is prime
	unsigned long long int num;
	num = p;
	for (unsigned long long int i = 3; i * i < num; i += 2) {
		//cout << "I " << i;
		if (num % i == 0) return false;
	}
	//if (count > 0) return false;
	//else
	return true;
}

unsigned long long int getP() {
	string nBin;
	unsigned long long int nDeci;
	srand(time(NULL));
	bool cond = false;
	while (!cond) {     //generates required binary and checks if the decimal equivalent is prime
		nBin = getBinary(32);
		nDeci = binToDeci(nBin);
		if (checkPrime(nDeci) == 1) cond = true;
	}
	return nDeci;
}

unsigned long long int getG(unsigned long long int nDeci) {
	unsigned long long int aForG, g;
	aForG = nDeci / 1000000;
	g = (aForG ^ 2) % nDeci;
	return g;
}


int main() {
	unsigned long long int p = getP();
	unsigned long long int g = getG(p);
	SHA1 s;
    string pw = "cscirocks1";
	string hash = s.sha1(pw);
	ofstream of;
	of.open("param.txt", std::ios_base::trunc);
	of << p << " " << g << " " << hash;
	of.close();

	return 0;
}








