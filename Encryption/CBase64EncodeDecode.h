#pragma once

#include "boinc_win.h"
#include <string>
using std::string;

#include <base64.h>
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

class CBase64EncodeDecode
{
public:
    string EncodeToBase64(string plainText);
    string DecodeFromBase64(string plainText);
    bool DecodeFromBase64(string encoded, byte* buffer, int len);
};

