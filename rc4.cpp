#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>

using namespace std;

string rc4(string toEN, string key)
{
	string out;
    unsigned char S[256];
	int i = 0, j = 0;
    for (i = 0; i < 256; i++)
        S[i] = i;
    for (i = 0; i < 256; i++)
    {
        j = (j + S[i] + key.at(i % key.length())) % 256;
        std::swap(S[i], S[j]);
    }
    j = 0;
    i = 0;
	for (int cc = 0; cc < toEN.length(); cc++)
	{
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		std::swap(S[i], S[j]);
		char temp = S[(S[i] + S[j]) % 256] ^ toEN[cc];
		out.push_back(temp);
	}

	return out;
}

