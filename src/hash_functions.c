#include <openssl/evp.h>

unsigned int size_md5() {
	return EVP_MD_size(EVP_md5());
}

unsigned char *calculate_md5(unsigned char *buf, unsigned int buf_size) {
	EVP_MD_CTX *mdctx;
	unsigned char *md5_digest;
	unsigned int md5_digest_len = size_md5();
    
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
	EVP_DigestUpdate(mdctx, buf, buf_size);
	md5_digest = (unsigned char *) malloc(md5_digest_len);
	EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
	EVP_MD_CTX_free(mdctx);
	return md5_digest;
}

unsigned int size_sha1() {
	return EVP_MD_size(EVP_sha1());
}

unsigned char *calculate_sha1(unsigned char *buf, unsigned int buf_size) {
	EVP_MD_CTX *mdctx;
	unsigned char *sha1_digest;
	unsigned int sha1_digest_len = size_sha1();
    
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
	EVP_DigestUpdate(mdctx, buf, buf_size);
	sha1_digest = (unsigned char *) malloc(sha1_digest_len);
	EVP_DigestFinal_ex(mdctx, sha1_digest, &sha1_digest_len);
	EVP_MD_CTX_free(mdctx);
	return sha1_digest;
}

unsigned int size_sha256() {
	return EVP_MD_size(EVP_sha256());
}

unsigned char *calculate_sha256(unsigned char *buf, unsigned int buf_size) {
	EVP_MD_CTX *mdctx;
	unsigned char *sha256_digest;
	unsigned int sha256_digest_len = size_sha256();
    
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, buf, buf_size);
	sha256_digest = (unsigned char *) malloc(sha256_digest_len);
	EVP_DigestFinal_ex(mdctx, sha256_digest, &sha256_digest_len);
	EVP_MD_CTX_free(mdctx);
	return sha256_digest;
}

unsigned int size_sha512() {
	return EVP_MD_size(EVP_sha512());
}

unsigned char *calculate_sha512(unsigned char *buf, unsigned int buf_size) {
	EVP_MD_CTX *mdctx;
	unsigned char *sha512_digest;
	unsigned int sha512_digest_len = size_sha512();
    
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
	EVP_DigestUpdate(mdctx, buf, buf_size);
	sha512_digest = (unsigned char *) malloc(sha512_digest_len);
	EVP_DigestFinal_ex(mdctx, sha512_digest, &sha512_digest_len);
	EVP_MD_CTX_free(mdctx);
	return sha512_digest;
}

