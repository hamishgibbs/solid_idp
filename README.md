# Solid IdP

A toy implementation of a Solid identity provider implemented in Python.

The goal of this library is to conform to the draft [SOLID-OIDC](https://solid.github.io/authentication-panel/solid-oidc/)  specification.

**Please note:** This library is in the very early stages of development. There are no guarantees of security or conformance with the draft [SOLID-OIDC](https://solid.github.io/authentication-panel/solid-oidc/) specification. The library is intended as an example implementation of client in the SOLID ecosystem.

# Features

The draft [SOLID-OIDC](https://solid.github.io/authentication-panel/solid-oidc/) specification defines the authentication flow for clients accessing resources hosted on SOLID servers. In this library, we implement an Identity Provider (IdP) which can register clients, display client WebID documents, and grant access tokens (DPoP-bound Access Tokens and OIDC ID Tokens).

Features (implemented [x] or planned [ ]) are as follows:

[ ] Register a WebID
[ ] Provide a SOLID oidcRegistration document (or client supplied parameters) [SOLID_OIDC §5.1](https://solid.github.io/authentication-panel/solid-oidc/#clientids-webid).
  [ ] Depends on resolving a WebID to an RDF document per [WebID 1.0 §6](https://www.w3.org/2005/Incubator/webid/spec/identity/#processing-the-webid-profile).
[ ] Provide clients with a DPoP-bound Access Token [SOLID_OIDC §6.1](https://solid.github.io/authentication-panel/solid-oidc/#tokens-access)<sup>†</sup>.
[ ] Provide clients with an OIDC ID Token [SOLID_OIDC §6.2](https://solid.github.io/authentication-panel/solid-oidc/#tokens-id)<sup>†</sup>.
[ ] Provides access to OpenID Provider Configuration Information at `/.well-known/openid-configuration` per [OpenID Connect Discovery 1.0 §4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).

<sup>†</sup>Considering the client provides one of the following:

* Client ID and Secret, and valid DPoP Proof.
* Client WebID with a proper registration and valid DPoP Proof.
* A Client ID of http://www.w3.org/ns/solid/terms#PublicOidcClient.

For more information on DPoP proofs see the draft: [OAuth 2.0 DPoP §4](https://tools.ietf.org/html/draft-ietf-oauth-dpop-02#section-4).
A DPoP proof is confirmed by the associated public key stored in the "jkt" member of the "cnf" claim in the DPoP proof. For more information see the draft: [OAuth 2.0 DPoP §7](https://tools.ietf.org/html/draft-ietf-oauth-dpop-02#section-7)
For a description of the overall authentication flow see [OpenID Connect Core 1.0 §3.1.1](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps)

# Resources

Implementation is based on the draft [SOLID-OIDC](https://solid.github.io/authentication-panel/solid-oidc/) specification.

The API interface is written using [FastAPI](https://github.com/tiangolo/fastapi).

Python RDF support is provided by [rdflib](https://github.com/RDFLib/rdflib).

This library is intended to pair with an [example implementation](https://github.com/hamishgibbs/solid_server) of a SOLID server.

# Contributions

This library is in the early stages of development and is intended to demonstrate the flow of SOLID client authentication.

Review, contributions, and discussion are welcome.

# Acknowledgements

This library relies on draft SOLID specifications authored by the [Solid project](https://solidproject.org/).
