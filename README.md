# rs-attenuable-jwt &emsp; [![CI](https://github.com/simplystated/rs-attenuable-jwt/actions/workflows/ci.yaml/badge.svg)](https://github.com/simplystated/rs-attenuable-jwt/actions/workflows/ci.yaml) [![Latest Version](https://img.shields.io/crates/v/attenuable-jwt.svg)](https://crates.io/crates/attenuable-jwt) [![Rust Documentation](https://docs.rs/attenuable-jwt/badge.svg)](https://docs.rs/attenuable-jwt) ![Crates.io](https://img.shields.io/crates/l/attenuable-jwt)
Attenuable JWT implementation in Rust

## What is attenuation good for?

Often, systems are constructed hierarchically such that one component might utilize another component to manage one entity on its behalf.
Attenuation allows a parent component to provide a more narrowly scoped token to a child, providing that child with access only to those resources it needs access to.
This dynamic enforcement of the principle of least privilege ensures that, even in the face of other programming errors, a parent component can ensure that a child only accesses those resources that it needs to in order to carry out the parent's requests.

For example, maybe a client system needs to manage users and documents.
There is no need for the users component to be able to change documents and vice versa.
The client may receive a full-access JWT asserting some `sub` and an audience of "api.example.com".
The client can then attenuate that JWT, adding a claim restricting the audience to "users.api.example.com" and can hand that attenuated JWT to the users component, ensuring that the users component can only make user requests.
Similarly the client can attenuate the same initial JWT, adding a claim restricting the audience to "documents.api.example.com" and hand that attenuated JWT to the docuemnts component.
The backend just needs to ensure that each service verifies the `aud` claim for JWTs that it receives.

Attenuable JWT makes no assumptions about the nature of "attenuation" in your use case.
Users of this library must provide a function that, given a set of existing claims and a set of attenuated claims, returns the active claims after attenuation.
In this case, that `resolve_claims` function would need to ensure that the attenuated `aud` claim is a subdomain of the existing `aud` claim.
In general, it is the responsibility of this `resolve_claims` function to ensure that attenuation is only restricting and never expanding the permissions associated with a token.

## Overview

Attenuable JWT allows you to provide a root JWT, signed however you'd like, with a set of claims.
One of those claims (`aky` for "attenuation key") is a JWK for a public attenuation key.
By providing clients with the JWT and the private attenuation key, a client can create another JWT with additional claims (again including a JWK for a new public attenuation key in the `aky` claim), signed by the private attenuation key (corresponding to the public attenuation key in the original JWT claims), and pass the chain of JWTs and the most recent private attenuation key on to another client.
When a client wants to use an attenuable JWT, it creates an envelope JWT with a `jwts` claim containing an array of the JWT chain and signs the envelope JWT with the final private attenuation key, corersponding to the public JWK in the `aky` claim of the final JWT in the `jwts` array.
Verification consists of:
1. Verifying that the envelope is signed with the final attenuation key.
2. Verifying that each jwt in the `jwts` chain is signed with a private key corresponding to the public key in the preceding JWT's `aky` claim.
3. Verifying that the first JWT in the `jwts` chain is signed with whatever root key is expected.
4. Verifying the usual `exp`, `nbf`, `iss`, `aud`, etc. claims.

## Security invariants

1. Once a JWT is `sealed`, no claims in the attenuation chain can be removed without access to the final private attenuation key
2. Only a client with a JWT chain and the private key corresponding to a `aky` JWK somewhere in the chain can add a claim
3. No client with a JWT chain and the private key corresponding to its final `aky` JWK can remove a prior claim or attenuation

### Invariant 1

Once a JWT is sealed, its full contents (the ordered array of inner JWTs) are signed with the attenuation key, whose public key is part of the signed payload.
The signature requires access to the final private attenuation key and ensures that no modifications can be made to the payload.

### Invariant 2

Verification ensures that the JWTs form a chain where each is signed with a private key corresponding to the public JWK in the previous JWT's `aky` claim.
A client needs access to a private key corresponding to some `aky` claim in the chain in order to add a JWT to the chain.
Therefore, without a private key corresponding to some `aky` claim in the chain, no client can add a JWT to the chain.

### Invariant 3

Clients can only add JWTs to the chain in a spot immediately after a JWT for which the client has a private attenuation key corresponding to that JWT's `aky` JWK claim.
Therefore, preservation of invariant 3 depends on ensuring that each client receives only the JWT chain and the private key corresponding to the JWK in the `aky` claim of the final JWT in that chain.
That ensures that each client can only add a JWT to the end of the chain of JWTs that it received.
Obviously, a client could remove some JWTs from the end of the chain but use of the token requires providing a sealed JWT, which requires a signature with the private key that corresponds to the public JWK in the final JWT's `aky` claim.
Therefore, if a client only has the private attenuation key corresponding the public JWK in the final JWT's `aky` claim, it MUST include all JWTs up to that final JWT in any envelope it hopes to pass verification.

## Prior art

The key chaining that is central to this scheme is inspired by [biscuit](https://www.biscuitsec.org/).
In addition to supporting attenuation, Biscuit comes with a really nice, declarative authorization language.
If you're in a position to use Biscuit, we recommend doing so.
If you need to stick with regular old JWTs but would like the benefits of chain of custody attenuation, attenuable-jwt might be the right choice.

## Contributing

### Running tests

Run tests with the `integration-test` feature enabled.
The integration tests depend on access to some internals that we do not expose to clients.

```bash
cargo test --features=integration-test
```
