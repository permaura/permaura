# Licensing

This repository is the Permaura™ gateway, and it is open source under the
[Apache License, Version 2.0](LICENSE).

Permaura's hosted service is proprietary and is not published. That line is not a compromise
between open and closed; it follows a single question, which is *what holds your credentials*.

## What is in this repository

The gateway, and everything it is built from:

| | |
| --- | --- |
| `services/gateway` | the local capability broker and its command-line surface, the `permaura` binary you run |
| `crates/permaura-core`, `-policy`, `-connectors`, `-credential-store` | the enforcement runtime: policy evaluation, sealed execution, redaction, the signed audit chain, credential custody |
| `crates/permaura-relay` | signature verification and the wire format for device approvals |
| `crates/permaura-daemon` | `permad`, a demo binary that serves the gateway router over a seeded in-memory estate with mock transports and the published demo bearer; `permaura start` does not use it |
| `packages/*` | the TypeScript SDK, the `@permaura/mcp-stdio` bridge, shared types |

This is the whole enforcement path. Every decision about whether an agent may do something is made
in code you can read here, and so is everything the gateway does with a secret: sealing and storing
it, opening it for a call or a vault export, injecting it into the call and redacting it from what
comes back. That holds wherever the gateway runs, on your own machine or as a hosted worker.

The gateway is not the only place a secret is ever in plaintext. A credential is plaintext in
whatever you enter it into before it reaches the gateway, and some of those are proprietary:

- The web console and the phone app. The phone reaches every gateway through permaura.com's broker,
  and the console does whenever the browser cannot reach the gateway directly. A credential added
  that way, and a vault bundle imported through the console with its passphrase, pass through the
  broker over TLS in a form the broker could read.
- The desktop app takes the passphrase a vault export is sealed under and hands it to the gateway
  on the same machine.

## What is not

The hosted control plane, the web console, billing, the connector signing service, and the desktop
and mobile apps are proprietary and live in private repositories. None of them are required to run
the gateway. It works standalone with no account, and signing in only adds the hosted
conveniences: remote access, the console, push approvals, and the managed worker tier.

## Why the line sits there

A security tool asking you to route your credentials through it should let you read the part that
holds them and acts with them. That part is the gateway, and it is here in full, with no held-back
enforcement module and no feature gated behind a license key in this repository. The proprietary
clients above, which a credential can pass through on its way in, are not.

The hosted service is the opposite case, and not because it holds nothing. A hosted worker keeps its
tenant's sealed vault and is handed the key that opens it, and permaura.com keeps a console session
for each linked self-run gateway that has no public address, which that gateway treats as a caller
from off the host however it arrives. Publishing the service's code would not let you verify what
actually runs on our servers. What you can verify is the gateway's half of every call it makes to
us: which requests leave your machine, what is in them, and what the gateway does with the answers.
That code is in this repository and you can read it without taking our word for anything.

Keeping the service proprietary is also what pays for the gateway to exist and stay maintained. We
would rather say that plainly than dress it up.

## Trademark

The Apache License covers the code. It does not cover the name or the logo, which are trademarks of
Pixelite SL. Forks are welcome and need their own name. See [TRADEMARK.md](TRADEMARK.md), which is
short and permissive.

## Note on earlier releases

Versions of the `@permaura/*` npm packages published before this repository went public were
released under the MIT license. Those releases stay MIT. Everything from here is Apache-2.0.
