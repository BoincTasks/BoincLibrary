#include "CBase64EncodeDecode.h"

// https://www.cryptopp.com/wiki/Base64Encoder
string CBase64EncodeDecode::EncodeToBase64(string plainText)
{
    string encoded;

    Base64Encoder encoder;
    encoder.Put((byte*)&plainText[0], plainText.size());
    encoder.MessageEnd();

    CryptoPP::lword  sizeEnc = encoder.MaxRetrievable();
    if (sizeEnc)
    {
        encoded.resize(sizeEnc);
        encoder.Get((byte*)&encoded[0], encoded.size());
    }
    return encoded;
}

// https://www.cryptopp.com/wiki/Base64Decoder
string CBase64EncodeDecode::DecodeFromBase64(string encoded)
{
    string decoded;

    Base64Decoder decoder;
    decoder.Put((byte*)encoded.data(), encoded.size());
    decoder.MessageEnd();

    CryptoPP::lword size = decoder.MaxRetrievable();
    if (size && size <= SIZE_MAX)
    {
        decoded.resize(size);
        decoder.Get((byte*)&decoded[0], decoded.size());
    }
    return decoded;
}

bool CBase64EncodeDecode::DecodeFromBase64(string encoded, byte* buffer, int len)
{
    Base64Decoder decoder;
    decoder.Put((byte*)encoded.data(), encoded.size());
    decoder.MessageEnd();

    CryptoPP::lword size = decoder.MaxRetrievable();
    if (size && size <= SIZE_MAX)
    {
        if (size > len) return false;
        decoder.Get(buffer, 255);
    }
    return true;
}

