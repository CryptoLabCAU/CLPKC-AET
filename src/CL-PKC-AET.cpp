// g++ -o CL-PKC-AET CL-PKC-AET.cpp -L. -lpbc -lgmp -lssl -lcrypto
// ./CL-PKC-AET ../params/e256.param
/**CL_PKC_AET.cpp**/

#include "../include/CL-PKC-AET.h"

#include <iostream>
#include <cstring>
#include <openssl/sha.h>
#include <fstream>
#include <string>
#include <time.h>
#include <queue>

using namespace std;

#define ITERCNT 10
#define TESTCNT 1000

CL_PKC_AET::CL_PKC_AET(/*int lambda = 80*/)
{
    this->init();
}

CL_PKC_AET::CL_PKC_AET(int argc, char **argv)
{
    pbc_demo_pairing_init(pairing, argc, argv);
    this->init();
}

CL_PKC_AET::~CL_PKC_AET()
{
    this->clear();
}

void CL_PKC_AET::init()
{
    element_init_G1(g, pairing);
    element_init_G1(g1, pairing);
    element_init_G1(g2, pairing);
    element_init_Zr(s1, pairing);
    element_init_Zr(s2, pairing);

    element_random(g);
    element_random(s1);
    element_random(s2);

    element_pow_zn(g1, g, s1); // g1 = g^s1
    element_pow_zn(g2, g, s2); // g2 = g^s2
    lenG1 = pairing_length_in_bytes_G1(pairing);
    lenGT = pairing_length_in_bytes_GT(pairing);
    lenZr = pairing_length_in_bytes_Zr(pairing);
}

void CL_PKC_AET::clear()
{
    element_clear(s1);
    element_clear(s2);
    element_clear(g);
    element_clear(g1);
    element_clear(g2);
    pairing_clear(pairing);
}

unsigned char *CL_PKC_AET::Extract_Private_Value()
{
    element_t xID;
    unsigned char *strXID = new unsigned char[lenZr];

    memset(strXID, 0x00, lenZr);

    element_init_Zr(xID, pairing);
    element_random(xID);

    element_to_bytes(strXID, xID);
    
    element_clear(xID);

    return strXID;
}

KEY *CL_PKC_AET::Extract_Partial_Private_Key(const unsigned char *ID)
{
    unsigned char *HashID = new unsigned char[SHA256_DIGEST_LENGTH];
    KEY *dk = new KEY;
    element_t HID, dk1, dk2;

    dk->key1 = new unsigned char[lenG1];
    dk->key2 = new unsigned char[lenG1];

    memset(dk->key1, 0x00, lenG1);
    memset(dk->key2, 0x00, lenG1);

    element_init_G1(HID, pairing);
    element_init_G1(dk1, pairing);
    element_init_G1(dk2, pairing);

    H1(ID, ID_SPACE, HashID, SHA256_DIGEST_LENGTH);

    element_from_hash(HID, HashID, SHA256_DIGEST_LENGTH);

    element_pow_zn(dk1, HID, s1); // dk1 = HID^s1
    element_pow_zn(dk2, HID, s2); // dk2 = HID^s2

    element_to_bytes(dk->key1, dk1);
    element_to_bytes(dk->key2, dk2);

    element_clear(HID);
    element_clear(dk1);
    element_clear(dk2);
    delete[] HashID;

    return dk;
}
KEY *CL_PKC_AET::Extract_Private_Key(const KEY dk, const unsigned char *x)
{
    KEY *sk = new KEY;
    element_t dk1, dk2;
    element_t sk1, sk2;
    element_t xID;

    sk->key1 = new unsigned char[lenG1];
    sk->key2 = new unsigned char[lenG1];

    memset(sk->key1, 0x00, lenG1);
    memset(sk->key2, 0x00, lenG1);

    element_init_G1(dk1, pairing);
    element_init_G1(dk2, pairing);
    element_init_G1(sk1, pairing);
    element_init_G1(sk2, pairing);
    element_init_Zr(xID, pairing);

    element_from_bytes(dk1, dk.key1);
    element_from_bytes(dk2, dk.key2);
    element_from_bytes(xID, (unsigned char *)x);

    element_pow_zn(sk1, dk1, xID); // sk1 = dk2^xID
    element_pow_zn(sk2, dk2, xID); // sk1 = dk2^xID

    element_to_bytes(sk->key1, sk1);
    element_to_bytes(sk->key2, sk2);

    element_clear(dk1);
    element_clear(dk2);
    element_clear(sk1);
    element_clear(sk2);
    element_clear(xID);

    return sk;
}


PK *CL_PKC_AET::Extract_Public_Key(const unsigned char *x)
{
    PK *pk = new PK;
    element_t X, pk1, pk2;
    element_t xID;

    pk->X = new unsigned char[lenG1];
    pk->pk1 = new unsigned char[lenG1];
    pk->pk2 = new unsigned char[lenG1];

    memset(pk->X, 0x00, lenG1);
    memset(pk->pk1, 0x00, lenG1);
    memset(pk->pk2, 0x00, lenG1);

    element_init_G1(X, pairing);
    element_init_G1(pk1, pairing);
    element_init_G1(pk2, pairing);
    element_init_Zr(xID, pairing);

    element_from_bytes(xID, (unsigned char *)x);

    element_pow_zn(X, g, xID);    // X = g^xID
    element_pow_zn(pk1, g1, xID); // pk1 = g1^xID
    element_pow_zn(pk2, g2, xID); // pk2 = g2^xID

    element_to_bytes(pk->X, X);
    element_to_bytes(pk->pk1, pk1);
    element_to_bytes(pk->pk2, pk2);

    element_clear(X);
    element_clear(pk1);
    element_clear(pk2);
    element_clear(xID);

    return pk;
}

CIPHER *CL_PKC_AET::Encrypt(const unsigned char *ID, PK pk, const unsigned char *M)
{

    element_t r1, r2;
    element_t HID, m;
    element_t C1, C2, C3;
    element_t C3_Pair, C3_Left, C3_Right;
    element_t C4_Pair;
    element_t tmp1, tmp2;
    element_t X, pk1, pk2;
    element_t verif1_pair1, verif1_pair2, verif2_pair1, verif2_pair2;

    CIPHER *C = new CIPHER;

    unsigned char *strR1 = new unsigned char[lenZr];
    unsigned char *HashID = new unsigned char[SHA256_DIGEST_LENGTH];

    unsigned char *strC3_Pair = new unsigned char[lenGT];
    unsigned char *strC3_Right = new unsigned char[SHA256_DIGEST_LENGTH];

    unsigned char *strC4_Left = new unsigned char[lenG1 + lenZr];
    unsigned char *strC4_Right = new unsigned char[lenG1 + lenZr];
    unsigned char *strC4_Pair = new unsigned char[lenGT];

    // // CIPHER C;
    C->C1 = new unsigned char[lenG1];         // g^r1
    C->C2 = new unsigned char[lenG1];         // g^r2
    C->C3 = new unsigned char[lenG1];         // M^r1 * H_2(e(hID, pk1)^r1)
    C->C4 = new unsigned char[lenG1 + lenZr]; // (M||r1) ^ H3(e(hID, pk2)^r2)

    memset(C->C1, 0x00, lenG1);
    memset(C->C2, 0x00, lenG1);
    memset(C->C3, 0x00, lenG1);
    memset(C->C4, 0x00, lenG1 + lenZr);
    memset(strR1, 0x00, lenZr);
    memset(strC3_Pair, 0x00, lenGT);
    memset(strC4_Left, 0x00, lenG1 + lenZr);
    memset(strC4_Pair, 0x00, lenGT);
    memset(strC4_Right, 0x00, lenG1 + lenZr);

    element_init_Zr(r1, pairing);
    element_init_Zr(r2, pairing);

    element_init_G1(HID, pairing);
    element_init_G1(m, pairing);
    element_init_GT(C3_Pair, pairing);
    element_init_GT(C4_Pair, pairing);
    element_init_G1(C1, pairing);
    element_init_G1(C2, pairing);
    element_init_G1(C3, pairing);
    element_init_G1(C3_Left, pairing);
    element_init_G1(C3_Right, pairing);
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);

    element_init_G1(X, pairing);
    element_init_G1(pk1, pairing);
    element_init_G1(pk2, pairing);

    element_init_GT(verif1_pair1, pairing);
    element_init_GT(verif1_pair2, pairing);
    element_init_GT(verif2_pair1, pairing);
    element_init_GT(verif2_pair2, pairing);

    element_from_bytes(X, pk.X);
    element_from_bytes(pk1, pk.pk1);
    element_from_bytes(pk2, pk.pk2);

    element_random(r1);
    element_random(r2);
    element_to_bytes(strR1, r1);

    /*
        check if pkID = (X, pk1, pk2) in G,
        e(X, g1) = e(pk1, g) and e(X, g2) = e(pk2, g).
    */
    element_pairing(verif1_pair1, X, g1);  // e(X, g1)
    element_pairing(verif1_pair2, pk1, g); // e(pk1, g)
    element_pairing(verif2_pair1, X, g2);  // e(X, g2)
    element_pairing(verif2_pair2, pk2, g); // e(pk2, g)

    if (element_cmp(verif1_pair1, verif1_pair2) || element_cmp(verif2_pair1, verif2_pair2))
    {
        printf("Encryption phase : verification fails\n");
        abort();
    }

    // C1 = g^r1, C2 = g^r2
    element_pow_zn(C1, g, r1);
    element_pow_zn(C2, g, r2);

    element_to_bytes(C->C1, C1);
    element_to_bytes(C->C2, C2);

    // HashID = H1(ID)
    H1(ID, ID_SPACE, HashID, SHA256_DIGEST_LENGTH);
    element_from_hash(HID, HashID, SHA256_DIGEST_LENGTH);

    element_from_bytes(m, (unsigned char *)M);

    // element_from_hash(m, (unsigned char*)M, lenG1);

    // C3 = M^r1 * H2(e(HID, pk1)^r1)
    element_pow_zn(tmp1, HID, r1);       // tmp1 = HID^r1
    element_pairing(C3_Pair, tmp1, pk1); // C3_pair = e(HID^r1, pk1) = e(HID, pk1)^r1
    element_to_bytes(strC3_Pair, C3_Pair);
    H2(strC3_Pair, lenGT, strC3_Right, SHA256_DIGEST_LENGTH);
    element_from_hash(C3_Right, strC3_Right, SHA256_DIGEST_LENGTH); // C3_Right = H2(C3_Pair)
    element_pow_zn(C3_Left, m, r1);                                 // C3_Left = M^r1
    element_mul(C3, C3_Left, C3_Right);                             // C3 = M^r1 * H2(e(HID, pk1)^r1)
    element_to_bytes(C->C3, C3);

    // C4 = (M||r1) ^ H3(e(hID,pk2)^r2)
    memcpy(strC4_Left, M, lenG1);
    memcpy(strC4_Left + sizeof(unsigned char) * lenG1, strR1, lenZr);

    element_pow_zn(tmp2, HID, r2); // tmp2 = HID^r2
    element_pairing(C4_Pair, tmp2, pk2);
    element_to_bytes(strC4_Pair, C4_Pair);

    H3(strC4_Pair, lenGT, strC4_Right, lenG1 + lenZr);

    for (int i = 0; i < lenG1 + lenZr; i++)
        C->C4[i] = strC4_Left[i] ^ strC4_Right[i];

    element_clear(r1);
    element_clear(r2);
    element_clear(HID);
    element_clear(m);
    element_clear(C1);
    element_clear(C2);
    element_clear(C3);
    element_clear(C3_Pair);
    element_clear(C3_Left);
    element_clear(C3_Right);
    element_clear(C4_Pair);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(pk1);
    element_clear(pk2);

    delete[] strR1;
    delete[] HashID;
    delete[] strC3_Pair;
    delete[] strC3_Right;
    delete[] strC4_Left;
    delete[] strC4_Right;
    delete[] strC4_Pair;

    return C;
}

unsigned char *CL_PKC_AET::Decrypt(const KEY sk, const CIPHER C)
{
    element_t C1, C2, C3;
    element_t C3_Pair, C3_Left, C3_Right;
    element_t C4_Pair;
    element_t sk1, sk2;
    element_t verifyC1, verifyC3;
    element_t m, r1;

    unsigned char *M = new unsigned char[lenG1];
    unsigned char *strR1 = new unsigned char[lenZr];
    unsigned char *strC3_Pair = new unsigned char[lenGT];
    unsigned char *strC3_Right = new unsigned char[SHA256_DIGEST_LENGTH];

    unsigned char *strC4_Left = new unsigned char[lenG1 + lenZr];
    unsigned char *strC4_Right = new unsigned char[lenG1 + lenZr];
    unsigned char *strC4_Pair = new unsigned char[lenGT];

    memset(M, 0x00, lenG1);
    memset(strC4_Left, 0x00, lenG1 + lenZr);
    memset(strC4_Pair, 0x00, lenGT);
    memset(strC4_Right, 0x00, lenG1 + lenZr);
    memset(strR1, 0x00, lenZr);

    element_init_G1(C1, pairing);
    element_init_G1(C2, pairing);
    element_init_G1(C3, pairing);
    element_init_G1(C3_Left, pairing);
    element_init_G1(C3_Right, pairing);
    element_init_GT(C3_Pair, pairing);
    element_init_GT(C4_Pair, pairing);
    element_init_G1(verifyC1, pairing);
    element_init_Zr(r1, pairing);
    element_init_G1(m, pairing);
    element_init_G1(verifyC3, pairing);
    element_init_G1(sk1, pairing);
    element_init_G1(sk2, pairing);

    element_from_bytes(C1, C.C1);
    element_from_bytes(C2, C.C2);
    element_from_bytes(C3, C.C3);
    element_from_bytes(sk1, sk.key1);
    element_from_bytes(sk2, sk.key2);

    element_pairing(C3_Pair, sk1, C1); // C3_Pair = e(sk1, C1)
    element_pairing(C4_Pair, sk2, C2); // C4_Pair = e(sk2, C2)

    element_to_bytes(strC3_Pair, C3_Pair);
    element_to_bytes(strC4_Pair, C4_Pair);

    H2(strC3_Pair, lenGT, strC3_Right, SHA256_DIGEST_LENGTH);
    element_from_hash(C3_Right, strC3_Right, SHA256_DIGEST_LENGTH); // C3_Right = H2(C3_Pair)

    H3(strC4_Pair, lenGT, strC4_Right, lenG1 + lenZr);

    for (int i = 0; i < lenG1 + lenZr; i++)
    {
        strC4_Left[i] = C.C4[i] ^ strC4_Right[i];
    }

    memcpy(M, strC4_Left, lenG1);
    memcpy(strR1, strC4_Left + sizeof(unsigned char) * lenG1, lenZr);

    element_from_bytes(r1, strR1);
    element_from_bytes(m, M);

    element_pow_zn(verifyC1, g, r1);    // g^r1
    element_pow_zn(C3_Left, m, r1);     // M^r1
    element_div(verifyC3, C3, C3_Left); //  H2(e(sk1,C1)) = C3 / M^r1

    if (element_cmp(C1, verifyC1) || element_cmp(verifyC3, C3_Right))
    {
        printf("Decryption phase : verification fails\n");
        abort();
    }

    element_clear(C1);
    element_clear(C2);
    element_clear(C3);
    element_clear(C3_Left);
    element_clear(C3_Right);
    element_clear(C3_Pair);
    element_clear(sk1);
    element_clear(sk2);
    element_clear(verifyC1);
    element_clear(m);
    element_clear(r1);
    element_clear(verifyC3);

    delete[] strR1;
    delete[] strC3_Pair;
    delete[] strC3_Right;
    delete[] strC4_Left;
    delete[] strC4_Right;
    delete[] strC4_Pair;

    return M;
}

unsigned char *CL_PKC_AET::aut1(const KEY sk)
{
    unsigned char *td = new unsigned char[lenG1];
    memcpy(td, sk.key1, lenG1);

    return td;
}

unsigned char *CL_PKC_AET::aut2(const KEY sk, const CIPHER C)
{
    unsigned char *td = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *strPair = new unsigned char[lenGT];

    element_t pair;
    element_t sk1;
    element_t C1;

    element_init_GT(pair, pairing);
    element_init_G1(sk1, pairing);
    element_init_G1(C1, pairing);

    memset(td, 0x00, SHA256_DIGEST_LENGTH);
    memset(strPair, 0x00, lenGT);

    element_from_bytes(sk1, sk.key1);
    element_from_bytes(C1, C.C1);

    element_pairing(pair, sk1, C1); // Pair = e(sk1, C1)
    element_to_bytes(strPair, pair);

    H2(strPair, lenGT, td, SHA256_DIGEST_LENGTH);

    element_clear(pair);
    element_clear(sk1);
    element_clear(C1);
    delete[] strPair;

    return td;
}
unsigned char *CL_PKC_AET::aut3i(const KEY sk, const CIPHER C)
{
    return aut2(sk, C);
}
unsigned char *CL_PKC_AET::aut3j(const KEY sk)
{
    return aut1(sk);
}
unsigned char **CL_PKC_AET::aut4(const KEY ski, const CIPHER Ci, const CIPHER Cj, element_t y)
{
    element_t td1, td2;
    element_t tmp1, tmp2;
    element_t pair;
    element_t Cj1;

    unsigned char *tdi2 = aut2(ski, Ci);
    unsigned char **td = new unsigned char *[2];
    td[0] = new unsigned char[lenG1]; // size check
    td[1] = new unsigned char[lenGT]; // size check

    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(td1, pairing);
    element_init_G1(Cj1, pairing);

    element_init_GT(td2, pairing);
    element_init_GT(pair, pairing);

    element_pow_zn(tmp1, g, y);                          // tmp1 = g^y
    element_from_hash(tmp2, tdi2, SHA256_DIGEST_LENGTH); // tmp2 = H2(e(ski1, Ci1))
    element_div(td1, tmp1, tmp2);
    element_to_bytes(td[0], td1);

    element_from_bytes(Cj1, Cj.C1);
    element_pairing(pair, tmp1, Cj1);
    element_to_bytes(td[1], pair);

    delete[] tdi2;
    element_clear(td1);
    element_clear(td2);
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(pair);
    element_clear(Cj1);

    return td;
}

bool CL_PKC_AET::test1(const CIPHER Ci, const unsigned char *_tdi, const CIPHER Cj, const unsigned char *_tdj)
{
    bool flag = false;
    element_t Xi, Xj;
    element_t cmpi, cmpj;
    element_t pairi, pairj;
    element_t hashi, hashj;
    element_t tdi, tdj;
    element_t Ci1, Cj1;
    element_t Ci3, Cj3;

    unsigned char *str_Pairi = new unsigned char[lenGT];
    unsigned char *str_Pairj = new unsigned char[lenGT];
    unsigned char *str_Hashi = new unsigned char[SHA256_DIGEST_LENGTH];
    unsigned char *str_Hashj = new unsigned char[SHA256_DIGEST_LENGTH];

    memset(str_Pairi, 0x00, lenGT);
    memset(str_Pairj, 0x00, lenGT);
    memset(str_Hashi, 0x00, SHA256_DIGEST_LENGTH);
    memset(str_Hashj, 0x00, SHA256_DIGEST_LENGTH);

    element_init_G1(Xi, pairing);
    element_init_G1(Xj, pairing);

    element_init_G1(hashi, pairing);
    element_init_G1(hashj, pairing);

    element_init_G1(tdi, pairing);
    element_init_G1(tdj, pairing);

    element_init_G1(Ci1, pairing);
    element_init_G1(Cj1, pairing);

    element_init_GT(cmpi, pairing);
    element_init_GT(cmpj, pairing);

    element_init_GT(pairi, pairing);
    element_init_GT(pairj, pairing);

    element_init_G1(Ci3, pairing);
    element_init_G1(Cj3, pairing);

    element_from_bytes(tdi, (unsigned char *)_tdi);
    element_from_bytes(tdj, (unsigned char *)_tdj);

    element_from_bytes(Ci1, Ci.C1);
    element_from_bytes(Cj1, Cj.C1);

    element_from_bytes(Ci3, Ci.C3);
    element_from_bytes(Cj3, Cj.C3);

    element_pairing(pairi, tdi, Ci1);
    element_pairing(pairj, tdj, Cj1);

    element_to_bytes(str_Pairi, pairi);
    element_to_bytes(str_Pairj, pairj);

    H2(str_Pairi, lenGT, str_Hashi, SHA256_DIGEST_LENGTH);
    H2(str_Pairj, lenGT, str_Hashj, SHA256_DIGEST_LENGTH);

    element_from_hash(hashi, str_Hashi, SHA256_DIGEST_LENGTH);
    element_from_hash(hashj, str_Hashj, SHA256_DIGEST_LENGTH);

    element_div(Xi, Ci3, hashi);
    element_div(Xj, Cj3, hashj);

    element_pairing(cmpi, Xi, Cj1);
    element_pairing(cmpj, Xj, Ci1);

    if (!element_cmp(cmpi, cmpj)) // return 1 if cmpi == cmpj
        flag = true;
    else
        flag = false;

    element_clear(Xi);
    element_clear(Xj);
    element_clear(cmpi);
    element_clear(cmpj);
    element_clear(pairi);
    element_clear(pairj);
    element_clear(hashi);
    element_clear(hashj);
    element_clear(tdi);
    element_clear(tdj);
    element_clear(Ci1);
    element_clear(Cj1);
    element_clear(Ci3);
    element_clear(Cj3);

    delete[] str_Pairi;
    delete[] str_Pairj;
    delete[] str_Hashi;
    delete[] str_Hashj;

    return flag;
}
bool CL_PKC_AET::test2(const CIPHER Ci, const unsigned char *_tdi, const CIPHER Cj, const unsigned char *_tdj)
{
    bool flag = false;
    element_t Xi, Xj;
    element_t cmpi, cmpj;
    element_t tdi, tdj;
    element_t Ci1, Cj1;
    element_t Ci3, Cj3;

    element_init_G1(Xi, pairing);
    element_init_G1(Xj, pairing);
    element_init_G1(tdi, pairing);
    element_init_G1(tdj, pairing);
    element_init_G1(Ci1, pairing);
    element_init_G1(Cj1, pairing);
    element_init_GT(cmpi, pairing);
    element_init_GT(cmpj, pairing);
    element_init_G1(Ci3, pairing);
    element_init_G1(Cj3, pairing);

    element_from_hash(tdi, (unsigned char *)_tdi, SHA256_DIGEST_LENGTH);
    element_from_hash(tdj, (unsigned char *)_tdj, SHA256_DIGEST_LENGTH);
    element_from_bytes(Ci1, Ci.C1);
    element_from_bytes(Cj1, Cj.C1);
    element_from_bytes(Ci3, Ci.C3);
    element_from_bytes(Cj3, Cj.C3);

    element_div(Xi, Ci3, tdi);
    element_div(Xj, Cj3, tdj);

    element_pairing(cmpi, Xi, Cj1);
    element_pairing(cmpj, Xj, Ci1);

    if (!element_cmp(cmpi, cmpj))
        flag = true;
    else
        flag = false;

    element_clear(Xi);
    element_clear(Xj);
    element_clear(cmpi);
    element_clear(cmpj);
    element_clear(tdi);
    element_clear(tdj);
    element_clear(Ci1);
    element_clear(Cj1);
    element_clear(Ci3);
    element_clear(Cj3);

    return flag;
}
bool CL_PKC_AET::test3(const CIPHER Ci, const unsigned char *_tdi, const CIPHER Cj, const unsigned char *_tdj)
{
    bool flag = false;
    element_t Xi, Xj;
    element_t cmpi, cmpj;
    element_t pairj;
    element_t hashj;
    element_t tdi, tdj;
    element_t Ci1, Cj1;
    element_t Ci3, Cj3;

    unsigned char *str_Pairj = new unsigned char[lenGT];
    unsigned char *str_Hashj = new unsigned char[SHA256_DIGEST_LENGTH];

    memset(str_Pairj, 0x00, lenGT);
    memset(str_Hashj, 0x00, SHA256_DIGEST_LENGTH);

    element_init_G1(Xi, pairing);
    element_init_G1(Xj, pairing);
    element_init_G1(hashj, pairing);
    element_init_G1(tdi, pairing);
    element_init_G1(tdj, pairing);
    element_init_G1(Ci1, pairing);
    element_init_G1(Cj1, pairing);
    element_init_GT(cmpi, pairing);
    element_init_GT(cmpj, pairing);
    element_init_GT(pairj, pairing);
    element_init_G1(Ci3, pairing);
    element_init_G1(Cj3, pairing);

    element_from_hash(tdi, (unsigned char *)_tdi, SHA256_DIGEST_LENGTH);
    element_from_bytes(tdj, (unsigned char *)_tdj);

    element_from_bytes(Ci1, Ci.C1);
    element_from_bytes(Cj1, Cj.C1);
    element_from_bytes(Ci3, Ci.C3);
    element_from_bytes(Cj3, Cj.C3);

    element_pairing(pairj, tdj, Cj1);

    element_to_bytes(str_Pairj, pairj);

    H2(str_Pairj, lenGT, str_Hashj, SHA256_DIGEST_LENGTH);

    element_from_hash(hashj, str_Hashj, SHA256_DIGEST_LENGTH);

    element_div(Xi, Ci3, tdi);
    element_div(Xj, Cj3, hashj);

    element_pairing(cmpi, Xi, Cj1);
    element_pairing(cmpj, Xj, Ci1);

    if (!element_cmp(cmpi, cmpj))
        flag = true;
    else
        flag = false;

    element_clear(Xi);
    element_clear(Xj);
    element_clear(cmpi);
    element_clear(cmpj);
    element_clear(pairj);
    element_clear(hashj);
    element_clear(tdi);
    element_clear(tdj);
    element_clear(Ci1);
    element_clear(Cj1);
    element_clear(Ci3);
    element_clear(Cj3);
    delete[] str_Pairj;
    delete[] str_Hashj;

    return flag;
}

bool CL_PKC_AET::test4(const CIPHER Ci, const unsigned char **_tdi, const CIPHER Cj, const unsigned char **_tdj)
{
    bool flag = false;
    element_t Xi, Xj;
    element_t cmp1, cmp2;
    element_t pairi, pairj;
    element_t tdi1, tdi2, tdj1, tdj2;
    element_t Ci1, Cj1;
    element_t Ci3, Cj3;

    element_init_G1(Xi, pairing);
    element_init_G1(Xj, pairing);
    element_init_G1(tdi1, pairing);
    element_init_GT(tdi2, pairing);
    element_init_G1(tdj1, pairing);
    element_init_GT(tdj2, pairing);
    element_init_G1(Ci1, pairing);
    element_init_G1(Cj1, pairing);

    element_init_GT(cmp1, pairing);
    element_init_GT(cmp2, pairing);

    element_init_GT(pairi, pairing);
    element_init_GT(pairj, pairing);
    element_init_G1(Ci3, pairing);
    element_init_G1(Cj3, pairing);

    element_from_bytes(tdi1, (unsigned char *)_tdi[0]);
    element_from_bytes(tdi2, (unsigned char *)_tdi[1]);
    element_from_bytes(tdj1, (unsigned char *)_tdj[0]);
    element_from_bytes(tdj2, (unsigned char *)_tdj[1]);
    element_from_bytes(Ci1, Ci.C1);
    element_from_bytes(Cj1, Cj.C1);
    element_from_bytes(Ci3, Ci.C3);
    element_from_bytes(Cj3, Cj.C3);

    element_mul(Xi, Ci3, tdi1);
    element_mul(Xj, Cj3, tdj1);

    element_pairing(pairi, Xi, Cj1);
    element_pairing(pairj, Xj, Ci1);

    element_div(cmp1, pairi, pairj);
    element_div(cmp2, tdi2, tdj2);

    if (!element_cmp(cmp1, cmp2))
        flag = true;
    else
        flag = false;

    element_clear(Xi);
    element_clear(Xj);
    element_clear(cmp1);
    element_clear(cmp2);
    element_clear(pairi);
    element_clear(pairj);
    element_clear(tdi1);
    element_clear(tdi2);
    element_clear(tdj1);
    element_clear(tdj2);
    element_clear(Ci1);
    element_clear(Cj1);
    element_clear(Ci3);
    element_clear(Cj3);

    return flag;
}

pairing_t *CL_PKC_AET::getPairing()
{
    return &this->pairing;
}

int CL_PKC_AET::getLenG1()
{
    return this->lenG1;
}
int CL_PKC_AET::getLenGT()
{
    return this->lenGT;
}
int CL_PKC_AET::getLenZr()
{
    return this->lenZr;
}

void CL_PKC_AET::H1(const unsigned char *src, const int slen, unsigned char *dest, int dlen)
{
    memset(dest, 0x00, dlen);

    SHA256(src, slen, dest);
}
void CL_PKC_AET::H2(const unsigned char *src, const int slen, unsigned char *dest, int dlen)
{
    memset(dest, 0x00, dlen);

    SHA256(src, slen, dest);
}
void CL_PKC_AET::H3(const unsigned char *src, const int slen, unsigned char *dest, int dlen)
{
    memset(dest, 0x00, dlen);
    for (int i = 0; i <= dlen / SHA512_DIGEST_LENGTH; i++)
    {
        unsigned char *pair_buf = new unsigned char[slen + 2];
        unsigned char *hash_buf = new unsigned char[SHA512_DIGEST_LENGTH];

        memset(pair_buf, 0x00, slen + 2);
        memset(hash_buf, 0x00, SHA512_DIGEST_LENGTH);

        memcpy(pair_buf, src, slen);

        strcat((char *)pair_buf, to_string(i).c_str());
        SHA512(pair_buf, slen + 2, hash_buf);

        if (i < dlen / SHA512_DIGEST_LENGTH)
            memcpy(dest + i * SHA512_DIGEST_LENGTH, hash_buf, SHA512_DIGEST_LENGTH);
        else
            memcpy(dest + i * SHA512_DIGEST_LENGTH, hash_buf, dlen - SHA512_DIGEST_LENGTH * i);

        delete[] pair_buf;
        delete[] hash_buf;
    }
}