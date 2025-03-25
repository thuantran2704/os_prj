all: project2

project2: main.c hash.c hash_functions.c hash.h hash_functions.h
	gcc main.c hash.c hash_functions.c -lcrypto -o project2

test:
	./project2 data/common-passwords.txt data/hashes.txt output.txt
	diff data/expected.txt output.txt
