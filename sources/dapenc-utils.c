//#include "dap_chain.h"
//#include "dap_chain_mine.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <fcntl.h>


#define LOG_TAG "dapenc-utils"

FILE* my_file_to_wite;


int main(int argc, const char *argv[]) {
    char* buf_encrypted = NULL;
    char* buf_decrypted = NULL;
    size_t buf_enc_size;
    size_t buf_dec_size;
    dap_enc_key_t *key;

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
                        /* */
            return 0;
        }



