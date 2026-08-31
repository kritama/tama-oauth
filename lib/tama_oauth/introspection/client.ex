defmodule TamaOAuth.Introspection.Client do
  @moduledoc """
  Performs a bounded authenticated OAuth token-introspection exchange.

  The caller supplies the trusted endpoint and claim bindings, an
  application-owned private signing key, time, and a replay-resistant
  assertion identifier. The package constructs the RFC 7662 form, mints the
  RFC 7523 client assertion, executes the bounded request, and validates the
  response.
  """

  alias TamaOAuth.{ClientAssertion, Error, Introspection}

  @max_identifier_bytes 2_048
  @max_deadline_ms 30_000
  @max_response_bytes 65_536
  @max_token_bytes 16_384

  @spec introspect(String.t(), keyword()) ::
          {:ok, map() | :inactive} | {:error, Error.t()}
  def introspect(token, opts) when is_binary(token) and is_list(opts) do
    with {:ok, context} <- context(opts),
         {:ok, raw_token} <-
           Introspection.parse_request(%{"token" => token},
             max_token_bytes: context.max_token_bytes
           ),
         {:ok, assertion, _claims} <- mint_assertion(context),
         {:ok, response} <- execute(request_context(raw_token, assertion, context), context),
         {:ok, document} <- decode_response(response, context.max_response_bytes) do
      validate_response(document, context)
    end
  end

  def introspect(_token, _opts), do: invalid_request(:introspection_client)

  defp context(opts) do
    context = %{
      endpoint: Keyword.get(opts, :endpoint),
      client_id: Keyword.get(opts, :client_id),
      key: Keyword.get(opts, :key),
      algorithm: Keyword.get(opts, :algorithm, "RS256"),
      algorithms: Keyword.get(opts, :algorithms, ["RS256"]),
      kid: Keyword.get(opts, :kid),
      jti: Keyword.get(opts, :jti),
      now: Keyword.get(opts, :now),
      ttl: Keyword.get(opts, :ttl, 60),
      max_assertion_bytes: Keyword.get(opts, :max_assertion_bytes, 16_384),
      issuer: Keyword.get(opts, :issuer),
      audience: Keyword.get(opts, :audience),
      scopes: Keyword.get(opts, :scopes),
      clock_skew_seconds: Keyword.get(opts, :clock_skew_seconds, 30),
      deadline_ms: Keyword.get(opts, :deadline_ms, 5_000),
      connect_timeout_ms: Keyword.get(opts, :connect_timeout_ms, 2_000),
      receive_timeout_ms: Keyword.get(opts, :receive_timeout_ms, 3_000),
      max_response_bytes: Keyword.get(opts, :max_response_bytes, 16_384),
      max_token_bytes: Keyword.get(opts, :max_token_bytes, @max_token_bytes),
      requester: Keyword.get(opts, :requester, &request/1)
    }

    if valid_context?(context), do: {:ok, context}, else: invalid_request(:introspection_client)
  end

  defp valid_context?(context) do
    valid_identifiers?(context) and valid_inputs?(context) and valid_bounds?(context)
  end

  defp valid_identifiers?(context) do
    bounded_string?(context.endpoint, @max_identifier_bytes) and
      bounded_string?(context.client_id, @max_identifier_bytes) and
      bounded_string?(context.issuer, @max_identifier_bytes) and
      bounded_string?(context.audience, @max_identifier_bytes)
  end

  defp valid_inputs?(context) do
    is_map(context.key) and is_list(context.scopes) and context.scopes != [] and
      is_integer(context.now) and context.now >= 0 and is_function(context.requester, 1)
  end

  defp valid_bounds?(context) do
    valid_request_timeouts?(context) and valid_size_bounds?(context) and
      is_integer(context.clock_skew_seconds) and context.clock_skew_seconds in 0..300
  end

  defp valid_request_timeouts?(context) do
    is_integer(context.deadline_ms) and context.deadline_ms in 1..@max_deadline_ms and
      is_integer(context.connect_timeout_ms) and
      context.connect_timeout_ms in 1..context.deadline_ms and
      is_integer(context.receive_timeout_ms) and
      context.receive_timeout_ms in 1..context.deadline_ms
  end

  defp valid_size_bounds?(context) do
    is_integer(context.max_response_bytes) and
      context.max_response_bytes in 1..@max_response_bytes and
      is_integer(context.max_token_bytes) and context.max_token_bytes in 1..@max_token_bytes
  end

  defp mint_assertion(context) do
    ClientAssertion.mint(context.client_id, context.endpoint, context.key,
      algorithm: context.algorithm,
      algorithms: context.algorithms,
      kid: context.kid,
      jti: context.jti,
      now: context.now,
      ttl: context.ttl,
      max_assertion_bytes: context.max_assertion_bytes
    )
  end

  defp request_context(token, assertion, context) do
    %{
      url: context.endpoint,
      form: [
        token: token,
        token_type_hint: "access_token",
        client_id: context.client_id,
        client_assertion_type: ClientAssertion.assertion_type(),
        client_assertion: assertion
      ],
      connect_timeout_ms: context.connect_timeout_ms,
      receive_timeout_ms: context.receive_timeout_ms,
      max_response_bytes: context.max_response_bytes
    }
  end

  defp execute(request_context, context) do
    task =
      Task.Supervisor.async_nolink(TamaOAuth.TaskSupervisor, fn ->
        context.requester.(request_context)
      end)

    case Task.yield(task, context.deadline_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, response}} -> {:ok, response}
      {:ok, {:error, _reason}} -> temporarily_unavailable(:introspection_request)
      {:exit, _reason} -> temporarily_unavailable(:introspection_request)
      nil -> temporarily_unavailable(:introspection_timeout)
      _result -> temporarily_unavailable(:introspection_request)
    end
  catch
    :exit, _reason -> temporarily_unavailable(:introspection_request)
  end

  defp request(context) do
    Req.post(
      url: context.url,
      form: context.form,
      headers: [{"accept", "application/json"}],
      redirect: false,
      retry: false,
      decode_body: false,
      into: &bounded_body(&1, &2, context.max_response_bytes),
      receive_timeout: context.receive_timeout_ms,
      connect_options: [timeout: context.connect_timeout_ms]
    )
  end

  defp decode_response(%{status: 200, headers: headers, body: body}, max_bytes)
       when is_binary(body) do
    with true <- byte_size(body) <= max_bytes,
         true <- json_content_type?(headers),
         {:ok, document} when is_map(document) <- Jason.decode(body) do
      {:ok, document}
    else
      _error -> invalid_token(:introspection_response)
    end
  end

  defp decode_response(%{status: 401}, _max_bytes),
    do: {:error, Error.new(:invalid_client, stage: :introspection_response)}

  defp decode_response(%{status: status}, _max_bytes)
       when status in [408, 429] or status in 500..599,
       do: temporarily_unavailable(:introspection_response)

  defp decode_response(_response, _max_bytes), do: invalid_token(:introspection_response)

  defp validate_response(document, context) do
    Introspection.validate_response(document,
      issuer: context.issuer,
      audience: context.audience,
      scopes: context.scopes,
      now: context.now,
      clock_skew_seconds: context.clock_skew_seconds
    )
  end

  defp bounded_body({:data, data}, {request, response}, max_body_bytes) do
    body = response.body <> data
    next = {request, %{response | body: body}}

    if byte_size(body) > max_body_bytes, do: {:halt, next}, else: {:cont, next}
  end

  defp json_content_type?(headers) do
    headers
    |> header_values("content-type")
    |> Enum.any?(fn value ->
      value
      |> String.split(";", parts: 2)
      |> hd()
      |> String.trim()
      |> String.downcase()
      |> Kernel.==("application/json")
    end)
  end

  defp header_values(headers, name) when is_map(headers),
    do: headers |> Map.get(name, []) |> List.wrap()

  defp header_values(headers, name) when is_list(headers) do
    for {key, value} <- headers, String.downcase(to_string(key)) == name, do: value
  end

  defp header_values(_headers, _name), do: []

  defp bounded_string?(value, max_bytes)
       when is_binary(value) and byte_size(value) in 1..max_bytes//1 do
    String.trim(value) != "" and not String.match?(value, ~r/[\x00-\x1F\x7F]/)
  end

  defp bounded_string?(_value, _max_bytes), do: false

  defp invalid_request(stage), do: {:error, Error.new(:invalid_request, stage: stage)}
  defp invalid_token(stage), do: {:error, Error.new(:invalid_token, stage: stage)}

  defp temporarily_unavailable(stage),
    do: {:error, Error.new(:temporarily_unavailable, stage: stage)}
end
