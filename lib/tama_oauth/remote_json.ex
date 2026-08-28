defmodule TamaOAuth.RemoteJSON do
  @moduledoc """
  Fetches bounded JSON documents through an SSRF-resistant network policy.

  DNS answers are validated before a request is made, the connection is pinned
  to a validated address, and redirects are revalidated. Callers may inject a
  resolver and requester for tests or controlled egress environments.
  """

  alias TamaOAuth.URI, as: OAuthURI

  @default_deadline_ms 5_000
  @default_max_body_bytes 65_536
  @default_max_redirects 3

  @type response :: %{
          body: binary(),
          document: map(),
          url: String.t(),
          cache_ttl: non_neg_integer() | nil
        }

  @spec fetch(term(), keyword()) :: {:ok, response()} | {:error, atom()}
  def fetch(url, opts \\ [])

  def fetch(url, opts) when is_binary(url) and is_list(opts) do
    deadline = Keyword.get(opts, :deadline, @default_deadline_ms)

    task =
      Task.Supervisor.async_nolink(TamaOAuth.TaskSupervisor, fn -> guarded_fetch(url, opts) end)

    case Task.yield(task, deadline) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      {:exit, _reason} -> {:error, :unavailable}
      nil -> {:error, :timeout}
    end
  catch
    :exit, _reason -> {:error, :unavailable}
  end

  def fetch(_url, _opts), do: {:error, :invalid_url}

  @doc false
  @spec public_address?(term()) :: boolean()
  def public_address?({_a, _b, _c, _d} = address), do: public_ipv4_address?(address)

  def public_address?({_a, _b, _c, _d, _e, _f, _g, _h} = address),
    do: public_ipv6_address?(address)

  def public_address?(_address), do: false

  defp public_ipv4_address?({a, b, c, d} = address)
       when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255 do
    not reserved_ipv4_address?(address)
  end

  defp public_ipv4_address?(_address), do: false

  defp reserved_ipv4_address?({a, _b, _c, _d}) when a in [0, 10, 127], do: true
  defp reserved_ipv4_address?({a, _b, _c, _d}) when a >= 224, do: true
  defp reserved_ipv4_address?({100, b, _c, _d}) when b in 64..127, do: true
  defp reserved_ipv4_address?({169, 254, _c, _d}), do: true
  defp reserved_ipv4_address?({172, b, _c, _d}) when b in 16..31, do: true
  defp reserved_ipv4_address?({192, b, _c, _d}) when b in [0, 168], do: true
  defp reserved_ipv4_address?({198, b, _c, _d}) when b in 18..19, do: true
  defp reserved_ipv4_address?({198, 51, 100, _d}), do: true
  defp reserved_ipv4_address?({203, 0, 113, _d}), do: true
  defp reserved_ipv4_address?(_address), do: false

  defp public_ipv6_address?({a, b, c, d, e, f, g, h} = address)
       when a in 0..0xFFFF and b in 0..0xFFFF and c in 0..0xFFFF and d in 0..0xFFFF and
              e in 0..0xFFFF and f in 0..0xFFFF and g in 0..0xFFFF and h in 0..0xFFFF do
    not reserved_ipv6_address?(address)
  end

  defp public_ipv6_address?(_address), do: false

  defp reserved_ipv6_address?({0, _b, _c, _d, _e, _f, _g, _h}), do: true

  defp reserved_ipv6_address?({a, _b, _c, _d, _e, _f, _g, _h})
       when a in 0xFC00..0xFDFF or a in 0xFE80..0xFEBF or a in 0xFF00..0xFFFF,
       do: true

  defp reserved_ipv6_address?({0x2001, 0x0DB8, _c, _d, _e, _f, _g, _h}), do: true
  defp reserved_ipv6_address?(_address), do: false

  @doc false
  @spec loopback_address?(term()) :: boolean()
  def loopback_address?({127, _b, _c, _d}), do: true
  def loopback_address?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  def loopback_address?(_address), do: false

  defp guarded_fetch(url, opts) do
    redirects = Keyword.get(opts, :redirects, @default_max_redirects)

    with :ok <- validate_origin(url, opts[:origin]),
         {:ok, uri, addresses} <- validate_fetch_url(url, opts),
         {:ok, response} <- with_host_slot(uri.host, fn -> request(uri, addresses, opts) end) do
      handle_response(response, url, Keyword.put(opts, :redirects, redirects))
    end
  rescue
    _ -> {:error, :unavailable}
  end

  defp handle_response(%{status: status} = response, url, opts) when status in 200..299 do
    body = response.body
    max_body_bytes = Keyword.get(opts, :max_body_bytes, @default_max_body_bytes)
    accepted = Keyword.get(opts, :content_types, ["application/json"])

    with true <- is_binary(body) and byte_size(body) <= max_body_bytes,
         true <- accepted_content_type?(response.headers, accepted),
         {:ok, document} when is_map(document) <- Jason.decode(body) do
      {:ok,
       %{
         body: body,
         document: document,
         url: url,
         cache_ttl: cache_ttl(response.headers)
       }}
    else
      _ -> {:error, :invalid_response}
    end
  end

  defp handle_response(%{status: status} = response, url, opts)
       when status in [301, 302, 303, 307, 308] do
    with redirects when redirects > 0 <- opts[:redirects],
         [location] <- header_values(response.headers, "location"),
         next_url <-
           url |> Elixir.URI.parse() |> Elixir.URI.merge(location) |> Elixir.URI.to_string(),
         :ok <- validate_origin(next_url, opts[:origin]) do
      guarded_fetch(next_url, Keyword.put(opts, :redirects, redirects - 1))
    else
      _ -> {:error, :invalid_response}
    end
  end

  defp handle_response(%{status: status}, _url, _opts) when status in 500..599,
    do: {:error, :unavailable}

  defp handle_response(_response, _url, _opts), do: {:error, :invalid_response}

  defp validate_origin(_url, nil), do: :ok

  defp validate_origin(url, origin) do
    if OAuthURI.same_origin?(url, origin), do: :ok, else: {:error, :invalid_origin}
  end

  defp validate_fetch_url(url, opts) do
    allow_local? = Keyword.get(opts, :allow_local?, false)
    resolver = Keyword.get(opts, :resolver, &resolve_addresses/1)

    with %Elixir.URI{host: host, userinfo: nil, fragment: nil} = uri when is_binary(host) <-
           Elixir.URI.parse(url),
         true <- OAuthURI.web_url?(url, allow_local?: allow_local?),
         {:ok, addresses} <- resolver.(host),
         true <- is_list(addresses) and addresses != [],
         true <- Enum.all?(addresses, &allowed_address?(&1, allow_local?)) do
      {:ok, uri, addresses}
    else
      _ -> {:error, :invalid_url}
    end
  end

  defp allowed_address?(address, true),
    do: public_address?(address) or loopback_address?(address)

  defp allowed_address?(address, false), do: public_address?(address)

  defp request(uri, addresses, opts) do
    requester = Keyword.get(opts, :requester, &default_request/3)

    Enum.reduce_while(addresses, {:error, :unavailable}, fn address, _last_error ->
      case requester.(uri, address, opts) do
        {:ok, response} -> {:halt, {:ok, normalize_response(response)}}
        {:error, _reason} -> {:cont, {:error, :unavailable}}
      end
    end)
  end

  defp default_request(uri, address, opts) do
    deadline = Keyword.get(opts, :deadline, @default_deadline_ms)
    max_body_bytes = Keyword.get(opts, :max_body_bytes, @default_max_body_bytes)

    Req.get(pinned_url(uri, address),
      headers: [{"host", uri.authority}],
      decode_body: false,
      redirect: false,
      retry: false,
      into: &bounded_body(&1, &2, max_body_bytes),
      receive_timeout: deadline,
      connect_options: connect_options(uri.host, address, deadline)
    )
  end

  defp normalize_response(%Req.Response{} = response) do
    %{status: response.status, headers: response.headers, body: response.body}
  end

  defp normalize_response(%{status: _status, headers: _headers, body: _body} = response),
    do: response

  defp pinned_url(uri, address) do
    uri
    |> Map.put(:host, address |> :inet.ntoa() |> to_string())
    |> Elixir.URI.to_string()
  end

  defp connect_options(host, address, deadline) do
    options = [timeout: deadline, hostname: host]

    if tuple_size(address) == 8,
      do: Keyword.put(options, :transport_opts, inet6: true),
      else: options
  end

  defp bounded_body({:data, data}, {request, response}, max_body_bytes) do
    body = response.body <> data
    next = {request, %{response | body: body}}

    if byte_size(body) > max_body_bytes, do: {:halt, next}, else: {:cont, next}
  end

  defp resolve_addresses(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> {:ok, [address]}
      {:error, _reason} -> {:ok, Enum.flat_map([:inet, :inet6], &resolve_family(host, &1))}
    end
  end

  defp resolve_family(host, family) do
    case :inet.getaddrs(String.to_charlist(host), family) do
      {:ok, addresses} -> addresses
      {:error, _reason} -> []
    end
  end

  defp with_host_slot(host, callback) do
    case :global.trans({__MODULE__, host}, callback, [node()]) do
      {:aborted, _reason} -> {:error, :unavailable}
      result -> result
    end
  end

  defp accepted_content_type?(headers, accepted) do
    headers
    |> header_values("content-type")
    |> Enum.any?(fn value ->
      value
      |> String.split(";", parts: 2)
      |> hd()
      |> String.trim()
      |> String.downcase()
      |> then(&(&1 in accepted))
    end)
  end

  defp cache_ttl(headers) do
    headers
    |> header_values("cache-control")
    |> Enum.find_value(&cache_control_ttl/1)
  end

  defp cache_control_ttl(value) do
    value
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.find_value(&cache_directive_ttl/1)
  end

  defp cache_directive_ttl("max-age=" <> seconds), do: parse_nonnegative_integer(seconds)
  defp cache_directive_ttl(_directive), do: nil

  defp parse_nonnegative_integer(value) do
    case Integer.parse(value) do
      {seconds, ""} when seconds >= 0 -> seconds
      _ -> nil
    end
  end

  defp header_values(headers, name) when is_map(headers),
    do: Map.get(headers, name, Map.get(headers, String.downcase(name), [])) |> List.wrap()

  defp header_values(headers, name) when is_list(headers) do
    for {key, value} <- headers,
        String.downcase(to_string(key)) == name,
        do: value
  end
end
