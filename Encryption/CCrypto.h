#pragma once

#include "boinc_win.h"
#include <string>
using std::string;

class CCrypto
{
int TAG_SIZE = 16;
public:
    string Encrypt(byte* pKey, byte* pIv, string toEncrypt);
    string Decrypt(byte* pKey, byte* pIv, string toDecrypt);
};

