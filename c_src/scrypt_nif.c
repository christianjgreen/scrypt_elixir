#include <erl_nif.h>
#include <errno.h>
#include <string.h>

#include "crypto_scrypt.h"

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

	N = (uint64_t)(1) << logN;

	enif_alloc_binary(dk_len, &bin_out);

	exitcode = crypto_scrypt(password.data, password.size, salt.data, salt.size,
							 N, r, p, bin_out.data, dk_len);
	if (exitcode == 0)
	{
		/* Success */
		return enif_make_binary(env, &bin_out);
	}
	else
	{
		enif_release_binary(&bin_out);
		return enif_make_int(env, errno);
	}
}

static ErlNifFunc nif_funcs[] = {{"hash_nif", 6, hash_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND}};

ERL_NIF_INIT(Elixir.Scrypt.NIF, nif_funcs, NULL, NULL, NULL, NULL)
