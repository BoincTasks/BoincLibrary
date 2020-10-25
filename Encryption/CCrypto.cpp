#include "CCrypto.h"

#include "filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "aes.h"
using CryptoPP::AES;

#include "gcm.h"
using CryptoPP::GCM;

// iv MUST change everytime it's used, but should be the same in Encrypt Decrypt
string CCrypto::Encrypt(byte* pKey, byte* pIv, string toEncrypt)
{
    string cipher;

    byte key[AES::DEFAULT_KEYLENGTH];
    ::memcpy(key, pKey, AES::DEFAULT_KEYLENGTH);
    byte iv[AES::BLOCKSIZE];
    ::memcpy(iv, pIv, AES::BLOCKSIZE);

    try
    {
        GCM< AES >::Encryption e;
        e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        // e.SpecifyDataLengths( 0, pdata.size(), 0 );

        StringSource(toEncrypt, true,
            new AuthenticatedEncryptionFilter(e,
                new StringSink(cipher), false, TAG_SIZE
            ) // AuthenticatedEncryptionFilter
        ); // StringSource
    }
    catch (CryptoPP::InvalidArgument& e)
    {
        return "IVA";
    }
    catch (CryptoPP::Exception& e)
    {
        return "EX";
    }
    return cipher;
}

string CCrypto::Decrypt(byte* pKey, byte* pIv, string cipher) {

    try
    {
        byte key[AES::DEFAULT_KEYLENGTH];
        ::memcpy(key, pKey, AES::DEFAULT_KEYLENGTH);
        byte iv[AES::BLOCKSIZE];
        ::memcpy(iv, pIv, AES::BLOCKSIZE);
        string rpdata;

        GCM< AES >::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        // d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );

        AuthenticatedDecryptionFilter df(d,
            new StringSink(rpdata),
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
            TAG_SIZE
        ); // AuthenticatedDecryptionFilter

        // The StringSource dtor will be called immediately
        //  after construction below. This will cause the
        //  destruction of objects it owns. To stop the
        //  behavior so we can get the decoding result from
        //  the DecryptionFilter, we must use a redirector
        //  or manually Put(...) into the filter without
        //  using a StringSource.
        StringSource(cipher, true,
            new Redirector(df /*, PASS_EVERYTHING */)
        ); // StringSource

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = df.GetLastResult();
        assert(true == b);

        return rpdata;
    }
    catch (CryptoPP::HashVerificationFilter::HashVerificationFailed& e)
    {
        return "HASH";
    }
    catch (CryptoPP::InvalidArgument& e)
    {
        return "IVA";
    }
    catch (CryptoPP::Exception& e)
    {
        return "EX";
    }
}