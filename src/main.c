#include <stdio.h>
#include <time.h>
#include <assert.h>

#include "hash.h"

// main function: do not modify!
int main(int argc, char **argv) {
	// time computation header
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	// end of time computation header

	assert(argc == 4);
	crack_hashed_passwords(argv[1], argv[2], argv[3]);

	// time computation footer
	clock_gettime(CLOCK_MONOTONIC, &end);
	printf("%.3f\n", ((double)end.tv_sec+1.0e-9*end.tv_nsec)-((double)start.tv_sec+1.0e-9*start.tv_nsec));
	// end of time computation footer
}

