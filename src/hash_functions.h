#ifndef __HASH_FUNCTIONS_HEADER__
#define __HASH_FUNCTIONS_HEADER__
 
unsigned int size_md5();
unsigned char *calculate_md5(unsigned char *buf, unsigned int buf_size);

unsigned int size_sha1();
unsigned char *calculate_sha1(unsigned char *buf, unsigned int buf_size);

unsigned int size_sha256();
unsigned char *calculate_sha256(unsigned char *buf, unsigned int buf_size);

unsigned int size_sha512();
unsigned char *calculate_sha512(unsigned char *buf, unsigned int buf_size);

#endif
