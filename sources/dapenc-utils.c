//#include "dap_chain.h"
//#include "dap_chain_mine.h"
#include "/home/avc/dev/dapenc-utils/libdap/crypto/dap_enc_sidh16.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <liboqs/kex/kex.h>

#define LOG_TAG "dapenc-utils"


FILE* my_file_to_wite;

struct kex_testcase {
    enum OQS_KEX_alg_name alg_name;
    unsigned char *seed;
    size_t seed_len;
    char *named_parameters;
    char *id;
    int run;
    int iter;
};

/* Add new testcases here */
struct kex_testcase kex_testcases[] = {
//#ifdef ENABLE_KEX_LWE_FRODO
//    {OQS_KEX_alg_lwe_frodo, (unsigned char *) "01234567890123456", 16, "recommended", "lwe_frodo_recommended", 0, 100},
//#endif
//#ifdef ENABLE_CODE_MCBITS
//    {OQS_KEX_alg_code_mcbits, NULL, 0, NULL, "code_mcbits", 0, 25},
//#endif
//#ifdef ENABLE_KEX_MLWE_KYBER
//    {OQS_KEX_alg_mlwe_kyber, NULL, 0, NULL, "mlwe_kyber", 0, 100},
//#endif
//#ifndef DISABLE_NTRU_ON_WINDOWS_BY_DEFAULT
//#ifdef ENABLE_KEX_NTRU
//    {OQS_KEX_alg_ntru, NULL, 0, NULL, "ntru", 0, 25},
//#endif
//#endif
//    {OQS_KEX_alg_rlwe_bcns15, NULL, 0, NULL, "rlwe_bcns15", 0, 100},
//#ifdef ENABLE_KEX_RLWE_MSRLN16
//    {OQS_KEX_alg_rlwe_msrln16, NULL, 0, NULL, "rlwe_msrln16", 0, 100},
//#endif
//#ifdef ENABLE_KEX_RLWE_NEWHOPE
//    {OQS_KEX_alg_rlwe_newhope, NULL, 0, NULL, "rlwe_newhope", 0, 100},
//#endif
#ifdef ENABLE_KEX_SIDH_CLN16
    {OQS_KEX_alg_sidh_cln16, NULL, 0, NULL, "sidh_cln16", 0, 10},
    {OQS_KEX_alg_sidh_cln16_compressed, NULL, 0, NULL, "sidh_cln16_compressed", 0, 10},
#endif
//#ifdef ENABLE_SIDH_IQC_REF
//    {OQS_KEX_alg_sidh_iqc_ref, NULL, 0, "params771", "sidh_iqc_ref", 0, 10},
//#endif
//#ifdef ENABLE_KEX_RLWE_NEWHOPE_AVX2
//    {OQS_KEX_alg_rlwe_newhope_avx2, NULL, 0, NULL, "rlwe_newhope_avx2", 0, 100},
//#endif

};

#define KEX_TEST_ITERATIONS 100
#define KEX_BENCH_SECONDS_DEFAULT 1




int main(int argc, const char *argv[]) {


    char* buf_encrypted = NULL;
    char* buf_decrypted = NULL;
    size_t buf_enc;
    size_t buf_dec;
    dap_enc_key_t *key;

    char buffer[512];
    log_it(L_INFO, "dapenc-utils version 0.0.1 \n");
                        if (strcmp(argv[2], "encrypt") == 0) {
                            if (argc > 4) {
                                /* encrypted/decrypted cmd param 4 */
                                log_it(L_INFO, "Encryption with '%s' method", argv[3]);
                                char buf_size = strlen(argv[4]);
                                buf_encrypted = (char *)calloc(1, buf_size * 4);
                                /* создаем файл с доступом    rw-r--r-- */
                                int fd = creat("aFile", 0644);
                                /* SIDH */
                                if (strcmp(argv[3], "SIDH") == 0) {
                                    key = dap_enc_key_new(DAP_ENC_KEY_TYPE_SIDH_CLN16);
                                    buf_enc = dap_enc_code(key, argv[4], buf_size, buf_encrypted, DAP_ENC_DATA_TYPE_RAW);
                                }
                                /* SIDH_B64 */
                                else if (strcmp(argv[3], "SIDH_B64")) {
                                   key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIDH_CLN16, 64);
                                   buf_enc = dap_enc_code(key, argv[4], buf_size, buf_encrypted, DAP_ENC_DATA_TYPE_B64);
                                }
                                write(fd, &buf_enc, sizeof buf_enc);
                                close(fd);
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
                                    buf_dec = dap_enc_decode(key, argv[4], buf_size, buf_decrypted, DAP_ENC_DATA_TYPE_RAW);
                                }
                                else if (strcmp(argv[3], "SIDH_B64") == 0) {
                                    buf_dec = dap_enc_decode(key, argv[4], buf_size, buf_decrypted, DAP_ENC_DATA_TYPE_B64);
                                }
                            }
                            else {
                                log_it(L_CRITICAL, "Command 'decrypt' needs to be specified. Set decryption type.");
                            }
                        }

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



