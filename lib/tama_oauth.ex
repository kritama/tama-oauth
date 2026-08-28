defmodule TamaOAuth do
  @moduledoc """
  Framework-neutral OAuth and MCP authorization primitives.

  `TamaOAuth` contains the bounded protocol mechanics shared by Memovee's
  authorization server and Tama's protected resource. It covers request
  validation, PKCE, client metadata and authentication, JWT/JWKS operations,
  metadata documents, refresh decisions, revocation, and introspection.

  Applications retain ownership of persistence, transactions, identity,
  lifecycle, policy, consent, caching, key custody, and web concerns. See the
  Architecture guide for the integration boundary.
  """
end
