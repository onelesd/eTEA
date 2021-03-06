#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "cipher_mode_cbc.h"
#include "tea.h"
#include "erl_nif.h"
#include "crypto.h"

#define ENCRYPT 0
#define DECRYPT 1
#define KEYSIZE 16
#define ROUNDS  32
#define BLKSIZE 8
#define PADCHARS 8

static ERL_NIF_TERM encrypt(ErlNifEnv* env,
                            int argc,
                            ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM bk, bi;

    ErlNifBinary binary_key, binary_data, binary_iv, binary_encrypted;

    size_t datalen = 0;
    int padchars = PADCHARS;

    unsigned char *encrypted_data = NULL;
    unsigned char *decrypted_data = NULL;
    ERL_NIF_TERM returned_data;

    struct tea *tea_context = NULL;

    unsigned char iv[9];
    unsigned char key[17];

    CipherAlgo cipher;

    /* Check the incoming paramaters. */
    if (argc != 2 ||
        !enif_inspect_binary(env, argv[0], &binary_data) ||
        !enif_is_map(env, argv[1])) {
        return enif_make_badarg(env);
    }

    /* Get the options from the options map.
       A minimum of 2 options are required:
          "key" -> the encryption key (string, length of 16)
          "iv"  -> the initialization vector (string, length of 8)
    */

    if (!enif_get_map_value(env, argv[1], enif_make_atom(env, "key"), &bk) ||
        !enif_get_map_value(env, argv[1], enif_make_atom(env, "iv"), &bi)) {
          printf("key exception on options map\n\r");
          fflush(stdout);
      return enif_make_badarg(env);
    }
    enif_inspect_binary(env, bk, &binary_key);
    enif_inspect_binary(env, bi, &binary_iv);

    /* Set the initialization vector and the key. */
    memset(iv, 0, sizeof(iv));
    memset(key, 0, sizeof(key));
    memcpy(iv, binary_iv.data, binary_iv.size);
    memcpy(key, binary_key.data, binary_key.size);

    /* Calculate the encrypted data size, with padding. */
    datalen = ((binary_data.size + 7) & ~7);
    if (datalen == binary_data.size) {
      datalen += 8;
    } else {
      padchars = datalen - binary_data.size;
    }

    /* Allocate a new binary for the encrypted data. */
    if (!enif_alloc_binary(datalen, &binary_encrypted)) {
      return enif_make_badarg(env);
    }

    /* Allocate storage for the data, both encrypted and not. */
    binary_encrypted.data = (unsigned char *)malloc(datalen);
    binary_encrypted.size = datalen;
    decrypted_data = (unsigned char *)malloc(datalen);
    memset(decrypted_data, padchars, datalen);
    memcpy(decrypted_data, binary_data.data, (binary_data.size));



    /* Initialize the CBC encryption algorithm interface. */
    cipher.name = "TEA";
    cipher.contextSize = sizeof(struct tea);
    cipher.blockSize = tea_blockSize();
    cipher.type = CIPHER_ALGO_TYPE_BLOCK;
    cipher.init = NULL;
    cipher.encryptBlock = tea_encryptBlock;
    cipher.decryptBlock = tea_decryptBlock;

    /* initialize the TEA algorithm context. */
    tea_context = tea_setup(binary_key.data, ROUNDS);

    /* Encrypt the data. */
    cbcEncrypt(&cipher, tea_context, iv, decrypted_data, binary_encrypted.data, datalen);

    returned_data = enif_make_string_len(env, binary_encrypted.data, datalen, ERL_NIF_LATIN1);

    /* Free allocated storage. */
    tea_free(tea_context);
    free(decrypted_data);

    /* Return the encrypted data. */
    return returned_data;

}

static ERL_NIF_TERM decrypt(ErlNifEnv* env,
                            int argc,
                            ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM bk, bi;

    ErlNifBinary binary_key, binary_data, binary_iv;

    size_t datalen = 0;
    size_t outlen = 0;

    unsigned char *encrypted_data = NULL;
    unsigned char *decrypted_data = NULL;
    unsigned char *returned_data = NULL;

    struct tea *tea_context = NULL;

    unsigned char iv[9];
    unsigned char key[17];

    CipherAlgo cipher;

    /* Check the incoming paramaters. */
    if (argc != 2 ||
        !enif_is_map(env, argv[1])) {
        return enif_make_badarg(env);
    }
    if (enif_is_list(env, argv[0])){
      enif_get_list_length(env, argv[0], &datalen);
      encrypted_data = (unsigned char *)malloc(datalen + 1);
      memset(encrypted_data, 0, datalen + 1);
      enif_get_string(env, argv[0], encrypted_data, datalen, ERL_NIF_LATIN1);
    } else {
      if (enif_inspect_binary(env, argv[0], &binary_data)) {
        datalen = binary_data.size;
        char *data = binary_data.data;
        encrypted_data = (unsigned char *)malloc(datalen + 1);
        memset(encrypted_data, 0, datalen + 1);
        memcpy(encrypted_data, data, datalen);
      } else {
        return enif_make_badarg(env);
      }
    }
    encrypted_data[datalen] = 0; /* ensure null termination */

    /* Get the options from the options map.
       A minimum of 2 options are required:
          "key" -> the encryption key (string, length of 16)
          "iv"  -> the initialization vector (string, length of 8)
    */

    if (!enif_get_map_value(env, argv[1], enif_make_atom(env, "key"), &bk) ||
        !enif_get_map_value(env, argv[1], enif_make_atom(env, "iv"), &bi)) {
          printf("key exception on options map\n\r");
          fflush(stdout);
      return enif_make_badarg(env);
    }
    enif_inspect_binary(env, bk, &binary_key);
    enif_inspect_binary(env, bi, &binary_iv);

    /* Set the initialization vector and the key. */
    memset(iv, 0, sizeof(iv));
    memset(key, 0, sizeof(key));
    memcpy(iv, binary_iv.data, binary_iv.size);
    memcpy(key, binary_key.data, binary_key.size);

    /* Initialize the CBC encryption algorithm interface. */
    cipher.name = "TEA";
    cipher.contextSize = sizeof(struct tea);
    cipher.blockSize = tea_blockSize();
    cipher.type = CIPHER_ALGO_TYPE_BLOCK;
    cipher.init = NULL;
    cipher.encryptBlock = tea_encryptBlock;
    cipher.decryptBlock = tea_decryptBlock;

    /* initialize the TEA algorithm context. */
    tea_context = tea_setup(binary_key.data, ROUNDS);

    /* Allocate storage for the decrypted data. */
    decrypted_data = (unsigned char *)malloc(datalen);

    /* Decrypt the data. */
    cbcDecrypt(&cipher, tea_context, iv, encrypted_data, decrypted_data, datalen);

    /* Depad if necessary. */
    int pad_len = decrypted_data[datalen - 1];
    if (pad_len < 9) {
      datalen -= pad_len;
      decrypted_data[datalen] = 0;
    }

    /* Prep the decrypted data for return. */
    returned_data = enif_make_string_len(env,
                                         (char *)decrypted_data,
                                         datalen,
                                         ERL_NIF_LATIN1);

    /* Free allocated resources. */
    free(tea_context);
    free(encrypted_data);
    free(decrypted_data);

    return returned_data;
}

static ErlNifFunc nif_funcs[] =
{
    {"encrypt", 2, encrypt},
    {"decrypt", 2, decrypt}
};
ERL_NIF_INIT(Elixir.ETEA, nif_funcs, NULL, NULL, NULL, NULL)
