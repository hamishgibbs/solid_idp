# Solid IdP

![GitHub Actions (Tests)](https://github.com/hamishgibbs/solid_idp/workflows/Tests/badge.svg)

An example implementation of a [Solid](https://solidproject.org/) identity provider implemented in Python.

The goal of this library is to conform to the draft [SOLID-OIDC](https://solid.github.io/authentication-panel/solid-oidc/)  specification.

**Please note:** This library is in the early stages of development. There are no guarantees of security or conformance with the draft [SOLID-OIDC](https://solid.github.io/authentication-panel/solid-oidc/) specification. The library is intended as an example implementation of client authentication in the SOLID ecosystem.

## See Also

This library is being developed alongside example implementations of:

* [Solid Resource Server](https://github.com/hamishgibbs/solid_server).
* [Solid Client](https://github.com/hamishgibbs/solid_client).


## Features

The draft [SOLID-OIDC](https://solid.github.io/authentication-panel/solid-oidc/) specification defines the authentication flow for clients accessing resources hosted on SOLID resource servers. In this library, we implement an Identity Provider (IdP) which can register agents, display agents' `PersonalProfileDocument`, and grant access tokens to clients using the [SOLID_OIDC authentication flow](https://solid.github.io/authentication-panel/solid-oidc) (DPoP-bound Access Tokens, OIDC ID Tokens, and refresh tokens).

Features (implemented or planned) are as follows:

- [X] Register an agent.  
- [X] Provide an agent's PersonalProfileDocument document [SOLID_OIDC Primer §2.1](https://solid.github.io/authentication-panel/solid-oidc-primer/#authorization-code-pkce-flow-step-2.1).  
- [X] Implements PKCE authentication flow to verify Client identity.  
- [X] Provide clients with a DPoP-bound Access Token [SOLID_OIDC §6.1](https://solid.github.io/authentication-panel/solid-oidc/#tokens-access)<sup>†</sup>.  
- [X] Optionally provides clients with an OIDC ID Token [SOLID_OIDC §6.2](https://solid.github.io/authentication-panel/solid-oidc/#tokens-id)<sup>†</sup>.  
- [X] Optionally provides clients with a refresh token<sup>†</sup>.  
- [X] Provides access to OpenID Provider Configuration Information at `/.well-known/openid-configuration` per [OpenID Connect Discovery 1.0 §4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).  
- [ ] Uses https to secure client-server communication per [SOLID §2.1](https://solid.github.io/specification/protocol#http).  
- [ ] Implements frontend interface for agent authentication.  
- [ ] Implements frontend interface for agent permission grants.  

<sup>†</sup>In the event that the client provides one of the following:

- [ ] Client ID and Secret, and valid DPoP Proof.
- [X] Client WebID with a proper registration and valid DPoP Proof.
- [ ] A Client ID of `http://www.w3.org/ns/solid/terms#PublicOidcClient`.

For more information on DPoP proofs see the draft: [OAuth 2.0 DPoP §4](https://tools.ietf.org/html/draft-ietf-oauth-dpop-02#section-4).  

For a description of the overall authentication flow see [OpenID Connect Core 1.0 §3.1.1](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps).  

Development of this library relies heavily on the [SOLID_OIDC Primer](https://solid.github.io/authentication-panel/solid-oidc-primer/).  

## Resources

This implementation is based on the draft [SOLID-OIDC](https://solid.github.io/authentication-panel/solid-oidc/) specification.

The API interface is written using [FastAPI](https://github.com/tiangolo/fastapi).

Python RDF support is provided by [rdflib](https://github.com/RDFLib/rdflib).

## Usage

The API is configured in `solid_idp/main.py`. To start the development server, initiate the server with `uvicorn`.

``` shell
uvicorn solid_idp.main:app --reload --port 8000
```

An example of an agent authentication flow is located in `examples/example_user.py`.  

An example of a client authentication flow is located in `examples/example_client.py`.  

Examples currently assume that the IdP is available at http://127.0.0.1:8000/ and the Client is available at http://127.0.0.1:8001/.

## Contributions

This library is in the early stages of development and is intended to demonstrate the flow of Solid client authentication. Review, contributions, and discussion are welcome.

## Acknowledgements

This library relies on draft SOLID specifications authored by the [Solid Project](https://solidproject.org/).
