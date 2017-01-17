#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "base64.h"
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

#define NIF_ATOM_DECL(a) ERL_NIF_TERM atom_ ## a;
#define NIF_ATOM_H_DECL(a) extern ERL_NIF_TERM atom_ ## a;
#define NIF_ATOM_INIT(a) atom_ ## a = enif_make_atom(env, #a);
#define NIF_ATOMS(A) \
        A(iv) \
        A(key)

NIF_ATOMS(NIF_ATOM_DECL)


/*
extern struct tea *tea_setup(unsigned char *, int);
extern void tea_free(struct tea *);
extern void tea_crypt(struct tea *, unsigned char *, unsigned char *, int);
*/

static ERL_NIF_TERM encrypt(ErlNifEnv* env,
                            int argc,
                            ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM bk, bi;

    ErlNifBinary binary_key, binary_data, binary_iv;

    size_t datasize = 0;
    size_t outlen = 0;
    int padchars = PADCHARS;

    unsigned char *encrypted_data = NULL;
    unsigned char *decrypted_data = NULL;
    unsigned char *returned_data = NULL;
    unsigned char *out_data = NULL;

    struct tea *tea_obj = NULL;

    unsigned char iv[9];
    unsigned char key[17];

    CipherAlgo cipher;

    /* Check the incoming paramaters. */
    if (argc != 2 ||
        !enif_inspect_binary(env, argv[0], &binary_data) ||
        !enif_is_map(env, argv[1])) {
        return enif_make_badarg(env);
    }

    /* Initialize some stack variables. */
    memset(iv, 0, sizeof(iv));
    memset(key, 0, sizeof(key));

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

    memcpy(iv, binary_iv.data, binary_iv.size);
    memcpy(key, binary_key.data, binary_key.size);

    /* Allocate and initialize some more stack variables. */
    datasize = ((binary_data.size + 7) & ~7);
    if (datasize == binary_data.size) {
      datasize += 8;
    } else {
      padchars = datasize - binary_data.size;
    }
    encrypted_data = (unsigned char *)malloc(datasize);
    decrypted_data = (unsigned char *)malloc(datasize);
    memset(decrypted_data, padchars, datasize);
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
    tea_obj = tea_setup(binary_key.data, ROUNDS);

    /* Encrypt the data. */
    cbcEncrypt(&cipher, tea_obj, iv, decrypted_data, encrypted_data, datasize);

    /* Base64 encode the encrypted data for return. */
    out_data = base64_encode(encrypted_data, datasize, &outlen);

    returned_data = enif_make_string_len(env,
                                         (char *)out_data,
                                         outlen,
                                         ERL_NIF_LATIN1);

    /* Free allocated storage. */
    tea_free(tea_obj);
    free(decrypted_data);
    free(encrypted_data);

    /* Return the encrypted data. */
    return returned_data;

}

static ERL_NIF_TERM decrypt(ErlNifEnv* env,
                            int argc,
                            ERL_NIF_TERM argv[])
{
    ErlNifBinary binary_key, binary_data;
    int datasize = 0;
    unsigned char *encrypted_data = NULL;
    unsigned char *decrypted_data = NULL;
    unsigned char *returned_data = NULL;
    unsigned char *key = NULL;
    struct tea *tea_obj = NULL;
    return enif_make_int(env, 69);
    if (argc !=2 ||
        !enif_inspect_binary(env, argv[0], &binary_key) ||
        !enif_inspect_binary(env, argv[1], &binary_data) ) {
        return enif_make_badarg(env);
    }
    /*
    datasize = binary_data.size;
    decrypted_data = (unsigned char *)malloc(datasize);
    encrypted_data = (unsigned char *)binary_data.data;
    tea_obj = tea_setup(key, ROUNDS);
    tea_crypt(tea_obj, encrypted_data, decrypted_data, ENCRYPT);
    returned_data = enif_make_string_len(env,
                                         (char *)decrypted_data,
                                         datasize,
                                         ERL_NIF_LATIN1);
    tea_free(tea_obj);
    free(decrypted_data);
    return returned_data;
    */
}

static ErlNifFunc nif_funcs[] =
{
    {"encrypt", 2, encrypt},
    {"decrypt", 2, decrypt}
};
ERL_NIF_INIT(Elixir.ETEA, nif_funcs, NULL, NULL, NULL, NULL)
