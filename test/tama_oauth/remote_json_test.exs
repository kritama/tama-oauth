defmodule TamaOAuth.RemoteJSONTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.RemoteJSON

  test "classifies public, private, reserved, and loopback addresses" do
    assert RemoteJSON.public_address?({8, 8, 8, 8})
    refute RemoteJSON.public_address?({10, 0, 0, 1})
    refute RemoteJSON.public_address?({100, 64, 0, 1})
    refute RemoteJSON.public_address?({192, 0, 2, 1})
    refute RemoteJSON.public_address?({203, 0, 113, 1})
    refute RemoteJSON.public_address?({0, 0, 0, 0, 0, 0, 0, 1})
    assert RemoteJSON.loopback_address?({127, 0, 0, 1})
  end

  test "fetches bounded JSON and derives cache max-age" do
    requester = fn uri, {8, 8, 8, 8}, _opts ->
      assert uri.host == "client.example"

      {:ok,
       %{
         status: 200,
         headers: %{
           "content-type" => ["application/json; charset=utf-8"],
           "cache-control" => ["public, max-age=120"]
         },
         body: ~s({"ok":true})
       }}
    end

    assert {:ok, response} =
             RemoteJSON.fetch("https://client.example/client.json",
               resolver: fn "client.example" -> {:ok, [{8, 8, 8, 8}]} end,
               requester: requester
             )

    assert response.document == %{"ok" => true}
    assert response.cache_ttl == 120
  end

  test "revalidates redirects and enforces an optional origin" do
    requests = start_supervised!({Agent, fn -> 0 end})

    requester = fn uri, _address, _opts ->
      request = Agent.get_and_update(requests, &{&1, &1 + 1})

      case request do
        0 ->
          {:ok,
           %{
             status: 302,
             headers: %{"location" => ["/final.json"]},
             body: ""
           }}

        1 ->
          assert uri.path == "/final.json"

          {:ok,
           %{
             status: 200,
             headers: %{"content-type" => ["application/json"]},
             body: ~s({"ok":true})
           }}
      end
    end

    opts = [
      origin: "https://client.example/client.json",
      resolver: fn _host -> {:ok, [{8, 8, 8, 8}]} end,
      requester: requester
    ]

    assert {:ok, %{url: "https://client.example/final.json"}} =
             RemoteJSON.fetch("https://client.example/client.json", opts)
  end

  test "rejects unsafe DNS answers before invoking the requester" do
    requester = fn _uri, _address, _opts -> flunk("unsafe address was requested") end

    assert {:error, :invalid_url} =
             RemoteJSON.fetch("https://client.example/client.json",
               resolver: fn _host -> {:ok, [{127, 0, 0, 1}]} end,
               requester: requester
             )
  end

  test "allows loopback HTTP only when explicitly enabled" do
    requester = fn _uri, {127, 0, 0, 1}, _opts ->
      {:ok,
       %{
         status: 200,
         headers: %{"content-type" => ["application/json"]},
         body: ~s({"local":true})
       }}
    end

    options = [
      resolver: fn _host -> {:ok, [{127, 0, 0, 1}]} end,
      requester: requester
    ]

    assert {:error, :invalid_url} = RemoteJSON.fetch("http://127.0.0.1:4000/doc", options)

    assert {:ok, %{document: %{"local" => true}}} =
             RemoteJSON.fetch("http://127.0.0.1:4000/doc", [allow_local?: true] ++ options)
  end

  test "rejects invalid media types and oversized bodies" do
    requester = fn _uri, _address, _opts ->
      {:ok,
       %{
         status: 200,
         headers: %{"content-type" => ["application/json-invalid"]},
         body: String.duplicate("x", 10)
       }}
    end

    options = [
      resolver: fn _host -> {:ok, [{8, 8, 8, 8}]} end,
      requester: requester,
      max_body_bytes: 5
    ]

    assert {:error, :invalid_response} =
             RemoteJSON.fetch("https://client.example/client.json", options)
  end
end
