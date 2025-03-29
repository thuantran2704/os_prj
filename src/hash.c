#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include "hash_functions.h"

#define KEEP 16                
#define MAX_PASS_SIZE 256
#define HASH_TABLE_SIZE 1024
#define WORKER_THREADS 11         // ensures total threads (including main) <= 12

struct cracked_hash {
    char hash[2*KEEP+1];
    char *password, *alg;
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = { calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512 };
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

// Use memcmp for comparing hash strings
int compare_hashes(char *a, char *b) {
    return memcmp(a, b, 2*KEEP) == 0;
}

// Global variables for hashed passwords
static int n_hashed;
static struct cracked_hash *cracked_hashes;

// worker queue definition
typedef struct node {
    char password[MAX_PASS_SIZE];
    struct node *next;
} node_t;

//initialize queue for threading
static node_t *queue_head = NULL;
static node_t *queue_tail = NULL;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static int finished_reading = 0;

// Enqueue a password into the work queue
static void enqueue(char *password) {
    node_t *new_node = malloc(sizeof(node_t));
    assert(new_node != NULL);
    strncpy(new_node->password, password, MAX_PASS_SIZE-1);
    new_node->password[MAX_PASS_SIZE-1] = '\0';
    new_node->next = NULL;
    
    // Lock the queue for thread safety
    pthread_mutex_lock(&queue_mutex);
    if(queue_tail == NULL) {
        queue_head = queue_tail = new_node;
    } else {
        queue_tail->next = new_node;
        queue_tail = new_node;
    }
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

// Dequeue a password from the work queue; returns NULL if finished and queue empty
static node_t *dequeue(void) {
    pthread_mutex_lock(&queue_mutex);
    while(queue_head == NULL && !finished_reading)
        pthread_cond_wait(&queue_cond, &queue_mutex);
    node_t *node = NULL;
    if(queue_head != NULL) {
        node = queue_head;
        queue_head = queue_head->next;
        if(queue_head == NULL)
            queue_tail = NULL;
    }
    pthread_mutex_unlock(&queue_mutex);
    return node;
}

// Hash Table for Hashed Passwords with Per-Bucket Locks
typedef struct hash_node {
    int index;
    struct hash_node *next;
} hash_node_t;

static hash_node_t *hash_table[HASH_TABLE_SIZE];
static pthread_mutex_t bucket_locks[HASH_TABLE_SIZE];  // one lock per bucket

// djb2 hash function for strings
static unsigned long djb2(const char *str) {
    unsigned long hash = 5381;
    int c;
    while((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

// Build the hash table from cracked_hashes and initialize bucket locks
static void build_hash_table(void) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++){
        hash_table[i] = NULL;
        pthread_mutex_init(&bucket_locks[i], NULL);
    }
    for (int i = 0; i < n_hashed; i++) {
        unsigned long h = djb2(cracked_hashes[i].hash);
        int bucket = h % HASH_TABLE_SIZE;
        hash_node_t *new_node = malloc(sizeof(hash_node_t));
        assert(new_node != NULL);
        new_node->index = i;
        new_node->next = hash_table[bucket];
        hash_table[bucket] = new_node;
    }
}

// Free the hash table and destroy bucket locks
static void free_hash_table(void) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        hash_node_t *curr = hash_table[i];
        while(curr) {
            hash_node_t *temp = curr;
            curr = curr->next;
            free(temp);
        }
        hash_table[i] = NULL;
        pthread_mutex_destroy(&bucket_locks[i]);
    }
}

// Worker Thread Function
static void *worker_func(void *arg) {
    (void)arg; // unused
    char hex_hash[2*KEEP+1];
    // Precomputed lookup table for hex digits
    static const char hex_digits[] = "0123456789abcdef";
    
    while (1) {
        node_t *node = dequeue();
        if (node == NULL) { // no more tasks and finished reading
            break;
        }
        // Cache the length to avoid repeated calls to strlen
        size_t len = strlen(node->password);
        // For each hash algorithm, compute the candidate hash
        for (int i = 0; i < n_algs; i++) {
            unsigned char *hash = fn[i]((unsigned char *)node->password, len);
            // Convert hash bytes to hex string using the lookup table
            for (int j = 0; j < KEEP; j++) {
                hex_hash[2*j]   = hex_digits[hash[j] >> 4];
                hex_hash[2*j+1] = hex_digits[hash[j] & 0x0F];
            }
            hex_hash[2*KEEP] = '\0';
            free(hash);
            
            // Quickly look up potential matches using the hash table
            unsigned long h_val = djb2(hex_hash);
            int bucket = h_val % HASH_TABLE_SIZE;
            
            pthread_mutex_lock(&bucket_locks[bucket]);
            hash_node_t *curr = hash_table[bucket];
            while (curr != NULL) {
                int idx = curr->index;
                if (cracked_hashes[idx].password == NULL &&
                    compare_hashes(hex_hash, cracked_hashes[idx].hash)) {
                    cracked_hashes[idx].password = strdup(node->password);
                    cracked_hashes[idx].alg = algs[i];
                    break; // Only record the first match for this hash
                }
                curr = curr->next;
            }
            pthread_mutex_unlock(&bucket_locks[bucket]);
        }
        free(node);
    }
    return NULL;
}


void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
    FILE *fp;
    char password[MAX_PASS_SIZE];
    char hex_hash[2*KEEP+1];           

    // load hashed passwords
    n_hashed = 0;
    fp = fopen(hashed_list, "r");
    assert(fp != NULL);
    while(fscanf(fp, "%s", hex_hash) == 1)
        n_hashed++;
    rewind(fp);
    cracked_hashes = malloc(n_hashed * sizeof(struct cracked_hash));
    assert(cracked_hashes != NULL);
    for (int i = 0; i < n_hashed; i++) {
        fscanf(fp, "%s", cracked_hashes[i].hash);
        cracked_hashes[i].password = NULL;
        cracked_hashes[i].alg = NULL;
    }
    fclose(fp);

    // build hash table for fast lookup
    build_hash_table();

    // create worker threads (New functionality added)
    pthread_t threads[WORKER_THREADS];
    for (int i = 0; i < WORKER_THREADS; i++)
        pthread_create(&threads[i], NULL, worker_func, NULL);
    
    // load common passwords and enqueue them
    fp = fopen(password_list, "r");
    assert(fp != NULL);
    while(fscanf(fp, "%s", password) == 1)
        enqueue(password); // Previously, passwords were hashed immediately inside the loop
    fclose(fp);

    // Signal that no more passwords will be enqueued 
    pthread_mutex_lock(&queue_mutex);
    finished_reading = 1;
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    // wait for all worker threads to finish
    for (int i = 0; i < WORKER_THREADS; i++)
        pthread_join(threads[i], NULL);

    // write results
    fp = fopen(output, "w");
    assert(fp != NULL);
    for (int i = 0; i < n_hashed; i++) {
        if (cracked_hashes[i].password == NULL)
            fprintf(fp, "not found\n");
        else
            fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
    }
    fclose(fp);

    // release allocated memory
    for (int i = 0; i < n_hashed; i++)
        free(cracked_hashes[i].password);
    free(cracked_hashes);

    //free hash_table preveting memory leaks
    free_hash_table();

    // Cleanup any remaining queue nodes (should be none)
    while(queue_head != NULL) {
        node_t *temp = queue_head;
        queue_head = queue_head->next;
        free(temp);
    }
}
