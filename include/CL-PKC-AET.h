/**CL-PKC-AET.h**/
#ifndef __CL_PKC_AET_H__
#define __CL_PKC_AET_H__

#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define ID_SPACE 32
#define Zp_SPACE 32 // n2

    typedef struct
    {
        unsigned char *C1;
        unsigned char *C2;
        unsigned char *C3;
        unsigned char *C4;
    } CIPHER;

    typedef struct
    {
        unsigned char *X;
        unsigned char *pk1;
        unsigned char *pk2;
    } PK;

    typedef struct
    {
        unsigned char *key1;
        unsigned char *key2;
    } KEY;

    class CL_PKC_AET
    {

    protected:
        pairing_t pairing;
        element_t s1, s2;    // master secret key
        element_t g, g1, g2; // public parameters
        int lenG1;
        int lenGT;
        int lenZr;

        

    public:
        CL_PKC_AET(/*int lambda = 80*/);
        CL_PKC_AET(int argc, char **argv);
        ~CL_PKC_AET();

        void init();
        void clear();

        CIPHER *Encrypt(const unsigned char *ID, const PK pk, const unsigned char *M);
        unsigned char *Decrypt(const KEY sk, const CIPHER C);

        unsigned char *Extract_Private_Value();
        KEY *Extract_Partial_Private_Key(const unsigned char *ID);
        KEY *Extract_Private_Key(const KEY dk, const unsigned char *x);
        PK *Extract_Public_Key(const unsigned char *x);

        unsigned char *aut1(const KEY sk);
        unsigned char *aut2(const KEY sk, const CIPHER C);
        unsigned char *aut3i(const KEY sk, const CIPHER C);
        unsigned char *aut3j(const KEY sk);
        unsigned char **aut4(const KEY ski, const CIPHER Ci, const CIPHER Cj, element_t y);
        pairing_t *getPairing();

        bool test1(const CIPHER Ci, const unsigned char *_tdi, const CIPHER Cj, const unsigned char *_tdj);
        bool test2(const CIPHER Ci, const unsigned char *_tdi, const CIPHER Cj, const unsigned char *_tdj);
        bool test3(const CIPHER Ci, const unsigned char *_tdi, const CIPHER Cj, const unsigned char *_tdj);
        bool test4(const CIPHER Ci, const unsigned char **_tdi, const CIPHER Cj, const unsigned char **_tdj);

        int getLenG1();
        int getLenGT();
        int getLenZr();

        void H1(const unsigned char *src, const int slen, unsigned char *dest, int dlen);
        void H2(const unsigned char *src, const int slen, unsigned char *dest, int dlen);
        void H3(const unsigned char *src, const int slen, unsigned char *dest, int dlen);
    };

#ifdef __cplusplus
}
#endif

#endif