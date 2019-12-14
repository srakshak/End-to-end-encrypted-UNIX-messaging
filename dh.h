#ifndef DH_H
#define DH_H

#include <string>

using namespace std;

void generateParams();
bool checkPrime(unsigned long long int p);
unsigned long long int binToDeci(string bin);
unsigned long long int getG(unsigned long long int nDeci);
unsigned long long int getP();
string getBinary(int l);

#endif
