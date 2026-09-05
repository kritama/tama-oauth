defmodule TamaOAuth.RemoteJSONTest do
  use ExUnit.Case, async: false

  alias TamaOAuth.RemoteJSON

  setup do
    original = Application.get_env(:tama_oauth, RemoteJSON)

    on_exit(fn ->
      if is_nil(original) do
        Application.delete_env(:tama_oauth, RemoteJSON)
      else
        Application.put_env(:tama_oauth, RemoteJSON, original)
      end
    end)

    :ok
  end

  test "classifies public, private, reserved, and loopback addresses" do
    assert RemoteJSON.public_address?({8, 8, 8, 8})
    refute RemoteJSON.public_address?({10, 0, 0, 1})
    refute RemoteJSON.public_address?({100, 64, 0, 1})
    refute RemoteJSON.public_address?({192, 0, 2, 1})
    refute RemoteJSON.public_address?({203, 0, 113, 1})
    refute RemoteJSON.public_address?({0, 0, 0, 0, 0, 0, 0, 1})
    assert RemoteJSON.loopback_address?({127, 0, 0, 1})
    assert RemoteJSON.private_network_address?({10, 0, 0, 1})
    assert RemoteJSON.private_network_address?({172, 31, 0, 1})
    assert RemoteJSON.private_network_address?({192, 168, 0, 1})
    assert RemoteJSON.private_network_address?({0xFD00, 0, 0, 0, 0, 0, 0, 1})
    refute RemoteJSON.private_network_address?({127, 0, 0, 1})
    refute RemoteJSON.private_network_address?({169, 254, 0, 1})
    refute RemoteJSON.private_network_address?({0xFE80, 0, 0, 0, 0, 0, 0, 1})
    refute RemoteJSON.private_network_address?({10, 0, 0, 256})
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

  test "public HTTPS fetches work with no trusted-origin configuration" do
    Application.delete_env(:tama_oauth, RemoteJSON)

    assert {:ok, %{document: %{"private" => true}}} =
             fetch_private("https://public.example/client.json", [{8, 8, 8, 8}])
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

  test "rejects private DNS answers by default" do
    assert {:error, :invalid_url} =
             fetch_private("https://app.localhost/client.json", [{172, 20, 0, 4}])
  end

  test "allows only exact configured HTTPS origins to use private DNS answers" do
    Application.put_env(:tama_oauth, RemoteJSON,
      trusted_private_origins: ["https://app.localhost"]
    )

    for address <- [
          {10, 0, 0, 2},
          {172, 20, 0, 4},
          {192, 168, 1, 3},
          {0xFD00, 0, 0, 0, 0, 0, 0, 2}
        ] do
      assert {:ok, %{document: %{"private" => true}}} =
               fetch_private("https://app.localhost/client.json", [address])
    end

    for url <- [
          "https://other.localhost/client.json",
          "https://app.localhost:444/client.json",
          "http://app.localhost/client.json",
          "https://172.20.0.4/client.json"
        ] do
      assert {:error, :invalid_url} = fetch_private(url, [{172, 20, 0, 4}])
    end
  end

  test "per-request origins override the application default with narrower policy" do
    Application.put_env(:tama_oauth, RemoteJSON,
      trusted_private_origins: ["https://app.localhost"]
    )

    assert {:error, :invalid_url} =
             fetch_private("https://app.localhost/client.json", [{172, 20, 0, 4}],
               trusted_private_origins: []
             )

    assert {:ok, _response} =
             fetch_private("https://peer.localhost/client.json", [{172, 20, 0, 5}],
               trusted_private_origins: ["https://peer.localhost"]
             )
  end

  test "fails closed for invalid, duplicate, excessive, and IP-literal trust entries" do
    invalid_sets = [
      "https://app.localhost",
      ["http://app.localhost"],
      ["https://user@app.localhost"],
      ["https://app.localhost/path"],
      ["https://app.localhost?debug=1"],
      ["https://app.localhost#fragment"],
      ["https://app..localhost"],
      ["https://172.20.0.4"],
      ["https://[fd00::1]"],
      ["https://app.localhost", "https://APP.localhost:443"],
      List.duplicate("https://app.localhost", 33)
    ]

    for trusted_private_origins <- invalid_sets do
      assert {:error, :invalid_url} =
               fetch_private("https://app.localhost/client.json", [{172, 20, 0, 4}],
                 trusted_private_origins: trusted_private_origins
               )
    end
  end

  test "rejects loopback, link-local, metadata, reserved, and mixed unsafe answers" do
    options = [trusted_private_origins: ["https://app.localhost"]]

    unsafe_answers = [
      [{127, 0, 0, 1}],
      [{169, 254, 169, 254}],
      [{100, 64, 0, 1}],
      [{192, 0, 2, 1}],
      [{0xFE80, 0, 0, 0, 0, 0, 0, 1}],
      [{172, 20, 0, 4}, {169, 254, 169, 254}]
    ]

    for addresses <- unsafe_answers do
      assert {:error, :invalid_url} =
               fetch_private("https://app.localhost/client.json", addresses, options)
    end
  end

  test "pins validated DNS answers while preserving the original hostname" do
    parent = self()

    requester = fn uri, address, _opts ->
      send(parent, {:request, uri, address})
      json_response()
    end

    assert {:ok, _response} =
             RemoteJSON.fetch("https://app.localhost/client.json",
               trusted_private_origins: ["https://app.localhost"],
               resolver: fn "app.localhost" -> {:ok, [{172, 20, 0, 4}]} end,
               requester: requester
             )

    assert_receive {:request, %URI{host: "app.localhost"}, {172, 20, 0, 4}}
  end

  test "trusted private redirects cannot leave the exact configured origin" do
    requester = fn _uri, _address, _opts ->
      {:ok,
       %{
         status: 302,
         headers: %{"location" => ["https://other.example/final.json"]},
         body: ""
       }}
    end

    assert {:error, :invalid_response} =
             RemoteJSON.fetch("https://app.localhost/client.json",
               trusted_private_origins: ["https://app.localhost"],
               resolver: fn
                 "app.localhost" -> {:ok, [{172, 20, 0, 4}]}
                 "other.example" -> {:ok, [{8, 8, 8, 8}]}
               end,
               requester: requester
             )
  end

  test "public redirects cannot enter a trusted private origin" do
    requester = fn
      %URI{host: "public.example"}, {8, 8, 8, 8}, _opts ->
        {:ok,
         %{
           status: 302,
           headers: %{"location" => ["https://app.localhost/private.json"]},
           body: ""
         }}

      _uri, _address, _opts ->
        flunk("trusted private redirect target must not be requested")
    end

    assert {:error, :invalid_response} =
             RemoteJSON.fetch("https://public.example/client.json",
               trusted_private_origins: ["https://app.localhost"],
               resolver: fn
                 "public.example" -> {:ok, [{8, 8, 8, 8}]}
                 "app.localhost" -> flunk("trusted private redirect target must not be resolved")
               end,
               requester: requester
             )
  end

  test "trusted private redirects remain available within the exact origin" do
    requester = fn
      %URI{path: "/client.json"}, {172, 20, 0, 4}, _opts ->
        {:ok,
         %{
           status: 302,
           headers: %{"location" => ["/final.json"]},
           body: ""
         }}

      %URI{path: "/final.json"}, {172, 20, 0, 4}, _opts ->
        json_response()
    end

    assert {:ok, %{url: "https://app.localhost/final.json"}} =
             RemoteJSON.fetch("https://app.localhost/client.json",
               trusted_private_origins: ["https://app.localhost"],
               resolver: fn "app.localhost" -> {:ok, [{172, 20, 0, 4}]} end,
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

  defp fetch_private(url, addresses, options \\ []) do
    RemoteJSON.fetch(
      url,
      Keyword.merge(
        [
          resolver: fn _host -> {:ok, addresses} end,
          requester: fn _, _, _ -> json_response() end
        ],
        options
      )
    )
  end

  defp json_response do
    {:ok,
     %{
       status: 200,
       headers: %{"content-type" => ["application/json"]},
       body: ~s({"private":true})
     }}
  end
end
