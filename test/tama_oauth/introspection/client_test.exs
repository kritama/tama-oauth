defmodule TamaOAuth.Introspection.ClientTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.{ClientAssertion, Error, SigningKey}
  alias TamaOAuth.Introspection.Client

  @now 1_787_900_000

  setup_all do
    {:ok, key} =
      SigningKey.generate({:rsa, 2_048},
        algorithm: "RS256",
        algorithms: ["RS256"],
        kid: "tama-introspection"
      )

    %{key: key}
  end

  test "builds the authenticated request and validates an active response", %{key: key} do
    test_pid = self()
    active = active_response()

    requester = fn context ->
      send(test_pid, {:request, context})
      {:ok, json_response(active)}
    end

    assert {:ok, ^active} =
             Client.introspect(
               "access-token",
               options(key, requester: requester)
             )

    assert_receive {:request, context}
    assert context.url == "https://memovee.example/auth/introspections"
    assert context.form[:token] == "access-token"
    assert context.form[:token_type_hint] == "access_token"
    assert context.form[:client_id] == "tama-mcp-app"
    assert context.form[:client_assertion_type] == ClientAssertion.assertion_type()

    assertion = context.form[:client_assertion]

    assert {:ok, %{"alg" => "RS256", "kid" => "tama-introspection"}} =
             Joken.peek_header(assertion)

    assert {:ok,
            %{
              "iss" => "tama-mcp-app",
              "sub" => "tama-mcp-app",
              "aud" => "https://memovee.example/auth/introspections",
              "jti" => "assertion-id",
              "iat" => @now,
              "exp" => expiration
            }} = Joken.peek_claims(assertion)

    assert expiration == @now + 60
  end

  test "accepts inactive responses", %{key: key} do
    requester = fn _context -> {:ok, json_response(%{"active" => false})} end

    assert {:ok, :inactive} =
             Client.introspect("access-token", options(key, requester: requester))
  end

  test "returns package errors for malformed and unavailable responses", %{key: key} do
    invalid = fn _context ->
      {:ok, %{status: 200, headers: %{"content-type" => ["text/plain"]}, body: "{}"}}
    end

    unavailable = fn _context ->
      {:ok, %{status: 503, headers: %{"content-type" => ["application/json"]}, body: "{}"}}
    end

    assert {:error, %Error{code: :invalid_token, stage: :introspection_response}} =
             Client.introspect("access-token", options(key, requester: invalid))

    assert {:error, %Error{code: :temporarily_unavailable, stage: :introspection_response}} =
             Client.introspect("access-token", options(key, requester: unavailable))
  end

  test "bounds response bodies and classifies client authentication failures", %{key: key} do
    oversized = fn _context ->
      {:ok,
       json_response(%{
         "active" => false,
         "padding" => String.duplicate("x", 128)
       })}
    end

    unauthorized = fn _context ->
      {:ok, %{status: 401, headers: %{"content-type" => ["application/json"]}, body: "{}"}}
    end

    assert {:error, %Error{code: :invalid_token, stage: :introspection_response}} =
             Client.introspect(
               "access-token",
               options(key, requester: oversized, max_response_bytes: 32)
             )

    assert {:error, %Error{code: :invalid_client, stage: :introspection_response}} =
             Client.introspect(
               "access-token",
               options(key, requester: unauthorized)
             )
  end

  test "enforces the total request deadline", %{key: key} do
    requester = fn _context ->
      Process.sleep(100)
      {:ok, json_response(%{"active" => false})}
    end

    assert {:error, %Error{code: :temporarily_unavailable, stage: :introspection_timeout}} =
             Client.introspect(
               "access-token",
               options(key,
                 requester: requester,
                 deadline_ms: 10,
                 connect_timeout_ms: 10,
                 receive_timeout_ms: 10
               )
             )
  end

  test "rejects missing application-owned trust and signing inputs", %{key: key} do
    assert {:error, %Error{code: :invalid_request, stage: :introspection_client}} =
             Client.introspect("access-token", Keyword.delete(options(key), :issuer))
  end

  defp options(key, overrides \\ []) do
    Keyword.merge(
      [
        endpoint: "https://memovee.example/auth/introspections",
        client_id: "tama-mcp-app",
        key: key,
        algorithm: "RS256",
        algorithms: ["RS256"],
        kid: "tama-introspection",
        jti: "assertion-id",
        now: @now,
        ttl: 60,
        issuer: "https://memovee.example",
        audience: "https://tama.example/mcp/app",
        scopes: ["mcp.message"],
        deadline_ms: 3_000,
        connect_timeout_ms: 1_000,
        receive_timeout_ms: 2_000
      ],
      overrides
    )
  end

  defp active_response do
    %{
      "active" => true,
      "iss" => "https://memovee.example",
      "sub" => "019963bd-16bc-7f01-b896-4a9c21824e3a",
      "aud" => "https://tama.example/mcp/app",
      "client_id" => "https://client.example/client.json",
      "scope" => "mcp.message",
      "jti" => "access-token-jti",
      "iat" => @now - 10,
      "exp" => @now + 300,
      "grant_id" => "019963bd-16bc-7f01-b896-4a9c21824e3b"
    }
  end

  defp json_response(document) do
    %{
      status: 200,
      headers: %{"content-type" => ["application/json; charset=utf-8"]},
      body: Jason.encode!(document)
    }
  end
end
