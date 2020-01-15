defmodule ScryptElixirTest do
  use ExUnit.Case, async: true

  describe "RFC test vectors" do
    # See https://tools.ietf.org/html/rfc7914.html#section-12
    test "Scrypt.hash/6 (P=\"\", S=\"\", logN=4, r=1, p=1, dklen=64)" do
      expected =
        <<119, 214, 87, 98, 56, 101, 123, 32, 59, 25, 202, 66, 193, 138, 4, 151, 241, 107, 72, 68,
          227, 7, 74, 232, 223, 223, 250, 63, 237, 226, 20, 66, 252, 208, 6, 157, 237, 9, 72, 248,
          50, 106, 117, 58, 15, 200, 31, 23, 232, 211, 224, 251, 46, 13, 54, 40, 207, 53, 226, 12,
          56, 209, 137, 6>>

      {:ok, result} = Scrypt.hash("", "", 4, 1, 1, 64)

      assert result == expected
    end

    test "Scrypt.hash/6 (P=\"password\", S=\"NaCl\", logN=10, r=8, p=16, dklen=64)" do
      expected =
        <<253, 186, 190, 28, 157, 52, 114, 0, 120, 86, 231, 25, 13, 1, 233, 254, 124, 106, 215,
          203, 200, 35, 120, 48, 231, 115, 118, 99, 75, 55, 49, 98, 46, 175, 48, 217, 46, 34, 163,
          136, 111, 241, 9, 39, 157, 152, 48, 218, 199, 39, 175, 185, 74, 131, 238, 109, 131, 96,
          203, 223, 162, 204, 6, 64>>

      {:ok, result} = Scrypt.hash("password", "NaCl", 10, 8, 16, 64)

      assert result == expected
    end

    test "Scrypt.hash/6 (P=\"pleaseletmein\", S=\"SodiumChloride\", logN=14, r=8, p=1, dklen=64)" do
      expected =
        <<112, 35, 189, 203, 58, 253, 115, 72, 70, 28, 6, 205, 129, 253, 56, 235, 253, 168, 251,
          186, 144, 79, 142, 62, 169, 181, 67, 246, 84, 93, 161, 242, 213, 67, 41, 85, 97, 63, 15,
          207, 98, 212, 151, 5, 36, 42, 154, 249, 230, 30, 133, 220, 13, 101, 30, 64, 223, 207, 1,
          123, 69, 87, 88, 135>>

      {:ok, result} = Scrypt.hash("pleaseletmein", "SodiumChloride", 14, 8, 1, 64)

      assert result == expected
    end

    test "Scrypt.hash/6 (P=\"pleaseletmein\", S=\"SodiumChloride\", logN=20, r=8, p=1, dklen=64)" do
      expected =
        <<33, 1, 203, 155, 106, 81, 26, 174, 173, 219, 190, 9, 207, 112, 248, 129, 236, 86, 141,
          87, 74, 47, 253, 77, 171, 229, 238, 152, 32, 173, 170, 71, 142, 86, 253, 143, 75, 165,
          208, 159, 250, 28, 109, 146, 124, 64, 244, 195, 55, 48, 64, 73, 232, 169, 82, 251, 203,
          244, 92, 111, 167, 122, 65, 164>>

      {:ok, result} = Scrypt.hash("pleaseletmein", "SodiumChloride", 20, 8, 1, 64)

      assert result == expected
    end
  end
end
