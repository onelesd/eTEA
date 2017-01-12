#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "tea.h"
#include "erl_nif.h"

#define ENCRYPT 0
#define DECRYPT 1
#define KEYSIZE 16
#define ROUNDS  32

extern struct tea *tea_setup(unsigned char *, int);
extern void tea_free(struct tea *);
extern void tea_crypt(struct tea *, unsigned char *, unsigned char *, int);

static ERL_NIF_TERM encrypt(ErlNifEnv* env,
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
    if (argc !=2 ||
        !enif_inspect_binary(env, argv[0], &binary_key) ||
        !enif_inspect_binary(env, argv[1], &binary_data) ) {
        return enif_make_badarg(env);
    }
    datasize = binary_data.size;
    encrypted_data = (unsigned char *)malloc(datasize);
    decrypted_data = (unsigned char *)binary_data.data;
    tea_obj = tea_setup(key, ROUNDS);
    tea_crypt(tea_obj, decrypted_data, encrypted_data, ENCRYPT);
    returned_data = enif_make_string_len(env,
                                         (char *)encrypted_data,
                                         datasize,
                                         ERL_NIF_LATIN1);
    tea_free(tea_obj);
    free(encrypted_data);
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
    if (argc !=2 ||
        !enif_inspect_binary(env, argv[0], &binary_key) ||
        !enif_inspect_binary(env, argv[1], &binary_data) ) {
        return enif_make_badarg(env);
    }
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
}

static ErlNifFunc nif_funcs[] =
{
    {"encrypt", 2, encrypt},
    {"decrypt", 2, decrypt}
};
ERL_NIF_INIT(Elixir.ETEA, nif_funcs, NULL, NULL, NULL, NULL)
