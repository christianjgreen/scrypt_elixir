defmodule ScryptTest do
  use ExUnit.Case, async: true

  describe "hash/6 RFC test vectors" do
    # See https://tools.ietf.org/html/rfc7914.html#section-12
    test "with RFC test vector (P=\"\", S=\"\", logN=4, r=1, p=1, dklen=64)" do
      expected =
        <<119, 214, 87, 98, 56, 101, 123, 32, 59, 25, 202, 66, 193, 138, 4, 151, 241, 107, 72, 68,
          227, 7, 74, 232, 223, 223, 250, 63, 237, 226, 20, 66, 252, 208, 6, 157, 237, 9, 72, 248,
          50, 106, 117, 58, 15, 200, 31, 23, 232, 211, 224, 251, 46, 13, 54, 40, 207, 53, 226, 12,
          56, 209, 137, 6>>

      assert Scrypt.hash("", "", 4, 1, 1, 64) == expected
    end

    test "with RFC test vector (P=\"password\", S=\"NaCl\", logN=10, r=8, p=16, dklen=64)" do
      expected =
        <<253, 186, 190, 28, 157, 52, 114, 0, 120, 86, 231, 25, 13, 1, 233, 254, 124, 106, 215,
          203, 200, 35, 120, 48, 231, 115, 118, 99, 75, 55, 49, 98, 46, 175, 48, 217, 46, 34, 163,
          136, 111, 241, 9, 39, 157, 152, 48, 218, 199, 39, 175, 185, 74, 131, 238, 109, 131, 96,
          203, 223, 162, 204, 6, 64>>

      assert Scrypt.hash("password", "NaCl", 10, 8, 16, 64) == expected
    end

    test "with RFC test vector (P=\"pleaseletmein\", S=\"SodiumChloride\", logN=14, r=8, p=1, dklen=64)" do
      expected =
        <<112, 35, 189, 203, 58, 253, 115, 72, 70, 28, 6, 205, 129, 253, 56, 235, 253, 168, 251,
          186, 144, 79, 142, 62, 169, 181, 67, 246, 84, 93, 161, 242, 213, 67, 41, 85, 97, 63, 15,
          207, 98, 212, 151, 5, 36, 42, 154, 249, 230, 30, 133, 220, 13, 101, 30, 64, 223, 207, 1,
          123, 69, 87, 88, 135>>

      assert Scrypt.hash("pleaseletmein", "SodiumChloride", 14, 8, 1, 64) == expected
    end

    test "with RFC test vector (P=\"pleaseletmein\", S=\"SodiumChloride\", logN=20, r=8, p=1, dklen=64)" do
      expected =
        <<33, 1, 203, 155, 106, 81, 26, 174, 173, 219, 190, 9, 207, 112, 248, 129, 236, 86, 141,
          87, 74, 47, 253, 77, 171, 229, 238, 152, 32, 173, 170, 71, 142, 86, 253, 143, 75, 165,
          208, 159, 250, 28, 109, 146, 124, 64, 244, 195, 55, 48, 64, 73, 232, 169, 82, 251, 203,
          244, 92, 111, 167, 122, 65, 164>>

      assert Scrypt.hash("pleaseletmein", "SodiumChloride", 20, 8, 1, 64) == expected
    end
  end

  describe "hash/6 errors" do
    test "raises an ArgumentError when logN is 0" do
      assert_raise ArgumentError, "Invalid scrypt parameters", fn ->
        Scrypt.hash("password", "salt", 0, 1, 1, 1)
      end
    end

    test "raises an ArgumentError when logN is too large" do
      assert_raise ArgumentError, "Scrypt parameters too large: ENOMEM", fn ->
        Scrypt.hash("password", "salt", 48, 1, 1, 1)
      end
    end

    test "raises an ArgumentError when logN greater than 63" do
      assert_raise ArgumentError, "Invalid scrypt parameters", fn ->
        Scrypt.hash("password", "salt", 64, 1, 1, 1)
      end
    end

    test "raises an ArgumentError when r is 0" do
      assert_raise ArgumentError, "Invalid scrypt parameters", fn ->
        Scrypt.hash("password", "salt", 1, 0, 1, 1)
      end
    end

    test "raises an ArgumentError when p is 0" do
      assert_raise ArgumentError, "Invalid scrypt parameters", fn ->
        Scrypt.hash("password", "salt", 1, 1, 0, 1)
      end
    end

    test "raises an ArgumentError when r * p is too large" do
      assert_raise ArgumentError, "Scrypt parameters too large: EFBIG", fn ->
        Scrypt.hash("password", "salt", 1, 16_777_216, 16_777_216, 1)
      end
    end
  end

  describe "verify?/6" do
    test "raises an argument error when given invalid scrypt parameters" do
      assert_raise ArgumentError, "Scrypt parameters too large: EFBIG", fn ->
        Scrypt.verify?("hash", "password", "salt", 1, 16_777_216, 16_777_216)
      end
    end

    test "returns false when given password does not match" do
      base_hash = Scrypt.hash("password", "salt", 1, 1, 1, 64)
      refute Scrypt.verify?(base_hash, "hunter2", "salt", 1, 1, 1)
    end

    test "returns false when given a matching password, but different parameters" do
      base_hash = Scrypt.hash("password", "salt", 1, 1, 1, 64)
      refute Scrypt.verify?(base_hash, "password", "salt", 2, 1, 1)
    end

    test "returns true when given a matching password" do
      base_hash = Scrypt.hash("password", "salt", 1, 1, 1, 64)
      assert Scrypt.verify?(base_hash, "password", "salt", 1, 1, 1)
    end
  end

  describe "kdf/4" do
    test "uses a random salt to generate hash" do
      first_hash = Scrypt.kdf("password", 1, 1, 1)
      second_hash = Scrypt.kdf("password", 1, 1, 1)

      refute first_hash == second_hash
    end
  end

  describe "kdf/5" do
    test "generates an RFC defined scrypt header" do
      salt = :crypto.strong_rand_bytes(32)

      assert <<header_name::binary-size(6), version::integer-size(8), log_n::integer-size(8),
               enc_r::binary-size(4), enc_p::binary-size(4), _salt::binary-size(32),
               _sha::binary-size(16),
               _hmac::binary-size(32)>> = Scrypt.kdf("password", salt, 1, 1, 1)

      assert header_name == "scrypt"
      assert version == 0
      assert log_n == 1
      assert enc_r == <<0, 0, 0, 1>>
      assert enc_p == <<0, 0, 0, 1>>
    end
  end

  describe "verify_kdf?" do
    setup do
      salt = :crypto.strong_rand_bytes(32)
      base_hash = Scrypt.kdf("password", salt, 1, 1, 1)
      [base_hash: base_hash]
    end

    test "raises an argument error when given invalid scrypt parameters" do
      bad_hash =
        <<"scrypt", 0, 1, 25, 153, 148, 0, 25, 153, 148, 0>> <> :crypto.strong_rand_bytes(80)

      assert_raise ArgumentError, "Scrypt parameters too large: EFBIG", fn ->
        Scrypt.verify_kdf?(bad_hash, "somepassword")
      end
    end

    test "returns false when given password does not match", %{base_hash: base_hash} do
      refute Scrypt.verify_kdf?(base_hash, "hunter2")
    end

    test "returns false when given a matching password, but different parameters", %{
      base_hash: base_hash
    } do
      bad_hash = :binary.replace(base_hash, <<"scrypt", 0, 1>>, <<"scrypt", 0, 2>>)
      refute Scrypt.verify_kdf?(bad_hash, "password")
    end

    test "returns true when given a matching password", %{base_hash: base_hash} do
      assert Scrypt.verify_kdf?(base_hash, "password")
    end
  end
end
