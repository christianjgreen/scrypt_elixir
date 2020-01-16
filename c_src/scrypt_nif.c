#include <erl_nif.h>
#include <string.h>

#include "crypto_scrypt.h"
#include "crypto_verify_bytes.h"
#include "insecure_memzero.h"
#include "sha256.h"
#include "sysendian.h"

#define KEY_LEN 64

ERL_NIF_TERM
hash_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	uint64_t N;
	uint32_t logN, r, p, dk_len;

	ErlNifBinary password, salt, bin_out;
	int exitcode;

	if (argc != 6 || !enif_inspect_binary(env, argv[0], &password) ||
		!enif_inspect_binary(env, argv[1], &salt) ||
		!enif_get_uint(env, argv[2], &logN) ||
		!enif_get_uint(env, argv[3], &r) ||
		!enif_get_uint(env, argv[4], &p) ||
		!enif_get_uint(env, argv[5], &dk_len))
		return enif_make_badarg(env);

	enif_alloc_binary(dk_len, &bin_out);

	N = 1 << logN;
	exitcode = crypto_scrypt(password.data, password.size, salt.data, salt.size,
							 N, r, p, bin_out.data, dk_len);

	if (exitcode == 0)
	{
		return enif_make_binary(env, &bin_out);
	}
	else
	{
		enif_release_binary(&bin_out);
		return enif_make_int(env, exitcode);
	}
}

ERL_NIF_TERM
kdf_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	uint64_t N;
	uint32_t logN, r, p;
	uint8_t hmac_buf[32], dk[KEY_LEN], *key_hmac = &dk[32];

	ErlNifBinary password, salt, bin_out;
	int exitcode;

	SHA256_CTX sha_ctx;
	HMAC_SHA256_CTX hmac_ctx;

	if (argc != 5 || !enif_inspect_binary(env, argv[0], &password) ||
		!enif_inspect_binary(env, argv[1], &salt) ||
		!enif_get_uint(env, argv[2], &logN) ||
		!enif_get_uint(env, argv[3], &r) ||
		!enif_get_uint(env, argv[4], &p))
		return enif_make_badarg(env);

	enif_alloc_binary(96, &bin_out);

	/* 14 -> 16384 */
	N = 1 << logN;
	exitcode = crypto_scrypt(password.data, password.size, salt.data, salt.size,
							 N, r, p, dk, KEY_LEN);

	memcpy(bin_out.data, "scrypt", 6);
	bin_out.data[6] = 0;
	bin_out.data[7] = logN;
	be32enc(&bin_out.data[8], r);
	be32enc(&bin_out.data[12], p);
	memcpy(&bin_out.data[16], salt.data, 32);

	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, bin_out.data, 48);
	SHA256_Final(hmac_buf, &sha_ctx);
	memcpy(&bin_out.data[48], hmac_buf, 16);

	HMAC_SHA256_Init(&hmac_ctx, key_hmac, 32);
	HMAC_SHA256_Update(&hmac_ctx, bin_out.data, KEY_LEN);
	HMAC_SHA256_Final(hmac_buf, &hmac_ctx);
	memcpy(&bin_out.data[KEY_LEN], hmac_buf, 32);

	insecure_memzero(dk, KEY_LEN);

	if (exitcode == 0)
	{
		return enif_make_binary(env, &bin_out);
	}
	else
	{
		enif_release_binary(&bin_out);
		return enif_make_int(env, exitcode);
	}
}

ERL_NIF_TERM
verify_kdf_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	uint8_t salt[32];
	uint64_t N;
	uint32_t r, p;
	uint8_t hmac_buf[32], dk[KEY_LEN], *key_hmac = &dk[32];

	ErlNifBinary hash, password;
	int exitcode;

	SHA256_CTX sha_ctx;
	HMAC_SHA256_CTX hmac_ctx;

	if (argc != 2 || !enif_inspect_binary(env, argv[0], &hash) ||
		!enif_inspect_binary(env, argv[1], &password))
		return enif_make_badarg(env);

	/* logN is stored in hash */
	N = 1 << hash.data[7];
	r = be32dec(&hash.data[8]);
	p = be32dec(&hash.data[12]);
	memcpy(salt, &hash.data[16], 32);

	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, hash.data, 48);
	SHA256_Final(hmac_buf, &sha_ctx);

	exitcode = crypto_scrypt(password.data, password.size, salt, 32, N, r, p, dk, KEY_LEN);

	if (exitcode == 0)
	{
		HMAC_SHA256_Init(&hmac_ctx, key_hmac, 32);
		HMAC_SHA256_Update(&hmac_ctx, hash.data, 64);
		HMAC_SHA256_Final(hmac_buf, &hmac_ctx);
		if (crypto_verify_bytes(hmac_buf, &hash.data[64], 32))
		{
			insecure_memzero(dk, KEY_LEN);
			return enif_make_atom(env, "false");
		}
		insecure_memzero(dk, KEY_LEN);
		return enif_make_atom(env, "true");
	}
	else
	{
		insecure_memzero(dk, KEY_LEN);
		return enif_make_int(env, exitcode);
	}
}

ERL_NIF_TERM
verify_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	uint64_t N;
	uint32_t logN, r, p;
	uint8_t *dk;

	ErlNifBinary hash, salt, password;
	int exitcode;

	if (argc != 6 || !enif_inspect_binary(env, argv[0], &hash) ||
		!enif_inspect_binary(env, argv[1], &password) ||
		!enif_inspect_binary(env, argv[2], &salt) ||
		!enif_get_uint(env, argv[3], &logN) ||
		!enif_get_uint(env, argv[4], &r) ||
		!enif_get_uint(env, argv[5], &p))
		return enif_make_badarg(env);

	/* logN is stored in hash */
	N = 1 << logN;

	dk = malloc(hash.size);

	exitcode = crypto_scrypt(password.data, password.size, salt.data, salt.size, N, r, p, dk, hash.size);

	if (exitcode == 0)
	{
		if (crypto_verify_bytes(hash.data, dk, hash.size))
		{
			insecure_memzero(dk, hash.size);
			free(dk);
			return enif_make_atom(env, "false");
		}
		insecure_memzero(dk, hash.size);
		free(dk);
		return enif_make_atom(env, "true");
	}
	else
	{
		insecure_memzero(dk, hash.size);
		free(dk);
		return enif_make_int(env, exitcode);
	}
}

static ErlNifFunc nif_funcs[] = {
	{"kdf_nif", 5, kdf_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"hash_nif", 6, hash_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"verify_kdf_nif", 2, verify_kdf_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"verify_nif", 6, verify_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND}};

ERL_NIF_INIT(Elixir.Scrypt.NIF, nif_funcs, NULL, NULL, NULL, NULL)