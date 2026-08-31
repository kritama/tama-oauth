defmodule TamaOAuth.SigningKeyTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.{Error, SigningKey}

  test "loads JSON and map private keys into an eligible normalized JWK" do
    raw = private_key()

    for source <- [raw, Jason.encode!(raw)] do
      assert {:ok, key} = SigningKey.load(source, options())
      assert key["kid"] == "signing-key"
      assert key["alg"] == "RS256"
      assert key["use"] == "sig"
      assert is_binary(key["d"])
      refute Map.has_key?(key, "key_ops")
    end
  end

  test "generates bounded development keys" do
    assert {:ok, %{"kty" => "RSA", "d" => private}} =
             SigningKey.generate({:rsa, 2_048}, options())

    assert is_binary(private)
  end

  test "rejects public, weak, symmetric, and mismatched keys with a bounded stage" do
    private = private_key()
    {_fields, public} = private |> JOSE.JWK.from_map() |> JOSE.JWK.to_public_map()
    weak = JOSE.JWK.generate_key({:rsa, 1_024}) |> JOSE.JWK.to_map() |> elem(1)

    symmetric = %{
      "kty" => "oct",
      "k" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    }

    mismatched = Map.put(private, "kid", "another-key")

    for key <- [public, weak, symmetric, mismatched] do
      assert {:error, %Error{code: :invalid_request, stage: :test_signing_key}} =
               SigningKey.load(key, Keyword.put(options(), :stage, :test_signing_key))
    end
  end

  defp private_key do
    {:rsa, 2_048}
    |> JOSE.JWK.generate_key()
    |> JOSE.JWK.to_map()
    |> elem(1)
  end

  defp options do
    [algorithm: "RS256", algorithms: ["RS256"], kid: "signing-key"]
  end
end
