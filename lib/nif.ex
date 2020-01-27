defmodule Scrypt.NIF do
  @compile {:autoload, false}
  @on_load {:init, 0}

  def init do
    :erlang.load_nif('./priv/scrypt_nif', 0)
  end

  def hash_nif(_, _, _, _, _, _)
  def hash_nif(_, _, _, _, _, _), do: :erlang.nif_error(:nif_not_loaded)
end
