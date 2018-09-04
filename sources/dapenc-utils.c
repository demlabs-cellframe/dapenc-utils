//#include "dap_chain.h"
//#include "dap_chain_mine.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <liboqs/crypto/rand/rand.h>
#include <liboqs/kex/kex.h>
#include <liboqs/ds_benchmark.h>

#include "dap_enc_sidh16.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_enc_key.h"
#include "dap_enc_base64.h"
#include "dap_enc.h"

#define LOG_TAG "dapenc-utils"

FILE* my_file_to_wite;

struct dapenc_testcase dapenc_testcases[] = {
    {OQS_KEX_alg_sidh_cln16, NULL, 0, NULL, "sidh_cln16", 0, 10},
    {OQS_KEX_alg_sidh_cln16_compressed, NULL, 0, NULL, "sidh_cln16_compressed", 0, 10}};

#define DAPENC_BENCH_SECONDS_DEFAULT 1

void print_message (const char *label, const char *str, size_t len) {
    size_t i;
    printf("%-20s (%4zu bytes):  ", (label), (size_t)(len));
    for (i = 0; i < (len); i++) {
        printf("%02X", ((unsigned char *) (str))[i]);
    }
    printf("\n");
}

dap_enc_key_t *test_k = NULL;


static int dapenc_test_correctness(OQS_RAND *rand, enum OQS_KEX_alg_name alg_name, const uint8_t *seed, const size_t seed_len, const char *named_parameters, const int print, unsigned long occurrences[256]) {

    size_t rc;

    void *alice_priv = NULL;
    uint8_t *alice_msg = NULL;
    size_t alice_msg_len;
    uint8_t *alice_key = NULL;
    size_t alice_key_len;

    uint8_t *bob_msg = NULL;
    size_t bob_msg_len;
    uint8_t *bob_key = NULL;
    size_t bob_key_len;

    // setup
    dap_enc_key_t test_k = dap_enc_sidh16_key_new_generate(test_k->data, test_k->data_size);
    if (test_k == NULL) {
       log_it(L_INFO, "new_method failed\n");
        rc = 0;
    }
    if (print) {
        printf("calculation for key exchange type %s\n", test_k->type);
    }
    /* Alice's initial message */
    rc = dap_enc_sidh16_encode(NULL, NULL, NULL, NULL);
    if (rc != 1) {
        log_it(L_INFO, "dap_enc_sidh16_encode failed\n");
        rc = 0;
    }

    if (print) {
        print_message("Alice message", alice_msg, alice_msg_len);
    }

    /* Bob's response */
    rc = dap_enc_sidh16_decode(NULL, NULL, NULL, NULL);
    if (rc != 1) {
        log_it(L_INFO, "dap_enc_sidh16_decode failed\n");
        rc = 0;
    }

    if (print) {
        print_message("Bob message", bob_msg, bob_msg_len);
        print_message("Bob session key", bob_key, bob_key_len);
    }

    /* Alice processes Bob's response */
    rc = OQS_KEX_sidh_cln16_alice_1(NULL, NULL, NULL, NULL, NULL, NULL);
    if (rc != 1) {
        log_it(L_INFO, "sidh_cln16_alice_1 failed\n");
        rc = 0;
    }

    if (print) {
        print_message("Alice session key", alice_key, alice_key_len);
    }

    // compare session key lengths and values
    if (alice_key_len != bob_key_len) {
        printf("ERROR: Alice's session key and Bob's session key are different lengths (%zu vs %zu)\n", alice_key_len, bob_key_len);
        rc = 0;
    }
    rc = memcmp(alice_key, bob_key, alice_key_len);
    if (rc != 0) {
        printf("ERROR: Alice's session key and Bob's session key are not equal\n");
        print_message("Alice session key", alice_key, alice_key_len);
        print_message("Bob session key", bob_key, bob_key_len);
        rc = 0;
    }
    if (print) {
        printf("Alice and Bob's session keys match.\n");
        printf("\n\n");
    }
    rc = 1;
    free(alice_msg);
    free(alice_key);
    free(bob_msg);
    free(bob_key);
    dap_enc_sidh16_key_delete(test_k);

    return rc;
}

static int dapenc_test_correct_wrapper(OQS_RAND *rand, enum OQS_KEX_alg_name alg_name, const uint8_t *seed, const size_t seed_len, const char *named_parameters, int iterations, bool quiet) {

    int ret, cnt_occur, cnt_iter;

    unsigned long occurrences[256];
    for (cnt_occur = 0; cnt_occur < 256; cnt_occur++) {
        occurrences[cnt_occur] = 0;
    }

    ret = dapenc_test_correct(rand, alg_name, seed, seed_len, named_parameters, quiet ? 0 : 1, occurrences);

    if (ret != 1) {
        ret = 0;
    }

    /* setup KEX */
    //new
    test_k = dap_enc_sidh16_key_new_generate(NULL, NULL);
    if (test_k == NULL) {
        ret = 0;
    }

    printf("Testing correct of key exchange type %s (params=%s) for %d iterations\n",
           test_k->type, named_parameters, iterations);
    for (cnt_iter = 0; cnt_iter < iterations; cnt_iter++) {
        ret = dapenc_test_correct(rand, alg_name, seed, seed_len, named_parameters, 0, occurrences);
        if (ret != 1) {
            ret = 0;
        }
    }
    printf("All session keys matched.\n");
    ret = 1;
    dap_enc_sidh16_key_delete(test_k);

    return ret;
}


static void cleanup_alice_0(OQS_KEX *kex, void *alice_priv, uint8_t *alice_msg) {
    free(alice_msg);
    dap_enc_sidh16_key_delete(test_k);
}

static void cleanup_bob(uint8_t *bob_msg, uint8_t *bob_key) {
    free(bob_msg);
    free(bob_key);
}


static int dapenc_bench_wrapper(OQS_RAND *rand, enum OQS_KEX_alg_name alg_name, const uint8_t *seed, const size_t seed_len, const char *named_parameters, const size_t seconds) {

    int rc;
    void *alice_priv = NULL;
    uint8_t *alice_msg = NULL;
    size_t alice_msg_len;
    uint8_t *alice_key = NULL;
    size_t alice_key_len;

    uint8_t *bob_msg = NULL;
    size_t bob_msg_len;
    uint8_t *bob_key = NULL;
    size_t bob_key_len;

    /* setup KEX */
    test_k = dap_enc_sidh16_key_new_generate(NULL, NULL);
    if (test_k == NULL) {
        printf("new_method failed\n");
        rc = 0;
    }
    printf("%-30s | %10s | %14s | %15s | %10s | %16s | %10s\n", test_k->type, "", "", "", "", "", "");

    TIME_OPERATION_SECONDS({
                               dap_enc  sidh16_encode(NULL, NULL, NULL, NULL);
                               cleanup_alice_0(test_k, alice_priv, alice_msg);
                           }, "alice 0", seconds);

    //alice_0
    dap_enc_sidh16_encode(NULL, NULL, NULL, NULL);
    TIME_OPERATION_SECONDS({
                               //bob
                               dap_enc_sidh16_decode(NULL, NULL, NULL, NULL);
                               cleanup_bob(bob_msg, bob_key);
                           }, "bob", seconds);

    //bob;
    dap_enc_sidh16_decode(NULL, NULL, NULL, NULL);
    TIME_OPERATION_SECONDS({
                               //alice_1
                               OQS_KEX_sidh_cln16_alice_1(NULL, NULL, NULL, NULL, NULL, NULL);
                               free(alice_key);
                           }, "alice 1", seconds);
    alice_key = NULL;


    printf("Exchange bytes: A->B: %zu, B->A: %zu, total: %zu; \n", alice_msg_len, bob_msg_len, alice_msg_len + bob_msg_len);

    rc = 1;

    free(alice_msg);
    free(alice_key);
    free(bob_msg);
    free(bob_key);
    dap_enc_sidh16_key_delete(test_k);

    return rc;
}

void print_help() {
    size_t cnt;

    printf("Usage: ./test_kex [options] [algorithms]\n");
    printf("\nOptions:\n");
    printf("  --quiet, -q\n");
    printf("    Less verbose output\n");
    printf("  --bench, -b\n");
    printf("    Run benchmarks\n");
    printf("  --seconds -s [SECONDS]\n");
    printf("    Number of seconds to run benchmarks (default==%d)\n", DAPENC_BENCH_SECONDS_DEFAULT);
    printf("  --mem-bench\n");
    printf("    Run memory benchmarks (run once and allocate only what is required)\n");
    printf("\nalgorithms:\n");
    size_t dapenc_testcases_len = sizeof(dapenc_testcases) / sizeof(struct dapenc_testcase);
    for (cnt = 0; cnt < dapenc_testcases_len; cnt++) {
        printf("  %s\n", dapenc_testcases[cnt].id);
    }
}


int main(int argc, const char *argv[]) {
    char* buf_encrypted = NULL;
    char* buf_decrypted = NULL;
    size_t buf_enc_size, buf_dec_size, cnt_testcases_len, j;
    dap_enc_key_t *key;
    int success = 1, i;
    bool run_all = true;
    bool quiet = false;
    size_t dapenc_testcases_len = sizeof(dapenc_testcases) / sizeof(struct dapenc_testcase);


    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "-help") == 0) || (strcmp(argv[i], "--help") == 0)) {
                print_help();
                return EXIT_SUCCESS;
            } else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
                quiet = true;
            } else {
             run_all = false;
            for (j = 0; j < dapenc_testcases_len; j++) {
                if (strcmp(argv[i], dapenc_testcases[j].id) == 0) {
                    dapenc_testcases[j].run = 1;
                }
            }
        }
    }

    // setup rand
    OQS_RAND *rand = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);
    if (rand == NULL) {
        success = 0;
        printf("ERROR!\n");
    }

    for (cnt_testcases_len = 0; cnt_testcases_len < dapenc_testcases_len; cnt_testcases_len++) {
        if (run_all || dapenc_testcases[cnt_testcases_len].run == 1) {
            int num_iter = dapenc_testcases[cnt_testcases_len].iter;
            success = dapenc_test_correct_wrapper(rand, dapenc_testcases[cnt_testcases_len].alg_name, dapenc_testcases[cnt_testcases_len].seed, dapenc_testcases[cnt_testcases_len].seed_len, dapenc_testcases[cnt_testcases_len].named_parameters, num_iter, quiet);
        }
        if (success != 1) {
            success = 0;
            printf("ERROR!\n");
        }
    }

    success = 1;
    OQS_RAND_free(rand);
    return (success == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
    }



    log_it(L_INFO, "dapenc-utils version 0.0.1 \n");

               my_file_to_wite = fopen("my_file.txt", "w");

                        /* encrypt and decrypt via cmd params */
                        if (strcmp(argv[2], "encrypt") == 0) {
                            if (argc > 4) {
                                /* What is supposed to be encrypted / decrypted ??? Let it be cmd param 4 */
                                log_it(L_INFO, "Encryption with '%s' method", argv[3]);
                                char buf_size = strlen(argv[4]);
                                buf_encrypted = (char *)calloc(1, buf_size * 4);
                                /* SIDH */
                                if (strcmp(argv[3], "SIDH") == 0) {
                                    key = dap_enc_key_new(DAP_ENC_KEY_TYPE_SIDH_CLN16);
                                    buf_enc_size = dap_enc_code(key, argv[4], buf_size, buf_encrypted, DAP_ENC_DATA_TYPE_RAW);
                                }
                                /* SIDH_B64 */
                                else if (strcmp(argv[3], "SIDH_B64")) {
                                   key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIDH_CLN16, 64);
                                   buf_enc_size = dap_enc_code(key, argv[4], buf_size, buf_encrypted, DAP_ENC_DATA_TYPE_B64);
                                }
                            }
                            else {
                                log_it(L_CRITICAL, "Command 'encrypt' needs to be specified. Set encryption type. ");
                            }
                        }
                        else if (strcmp(argv[2], "decrypt") == 0) {
                            if (argc > 4) {
                                log_it(L_INFO, "Decryption with '%s' method", argv[3]);
                                char buf_size = strlen(argv[4]);
                                buf_decrypted = (char *)calloc(1, buf_size * 4);
                                if (strcmp(argv[3], "SIDH") == 0) {
                                    buf_dec_size = dap_enc_decode(key, argv[4], buf_size, buf_decrypted, DAP_ENC_DATA_TYPE_RAW);
                                }
                                else if (strcmp(argv[3], "SIDH_B64") == 0) {
                                    buf_dec_size = dap_enc_decode(key, argv[4], buf_size, buf_decrypted, DAP_ENC_DATA_TYPE_B64);
                                }
                            }
                            else {
                                log_it(L_CRITICAL, "Command 'decrypt' needs to be specified. Set decryption type.");
                            }
                        }
                        /* Do smth with obtained buffers*/
                        if (buf_encrypted)
                        {
                            free(buf_encrypted);
                            buf_encrypted = NULL;
                        }
                        if (buf_decrypted)
                        {
                            free(buf_decrypted);
                            buf_decrypted = NULL;
                        }
            return 0;
        }



