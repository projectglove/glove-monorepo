# Building Glove

You will need an x86-64 machine with docker installed to build Glove:

```shell
./build.sh
```

This will build the service, enclave and client CLI binaries. The enclave image measurement, `PCR0`, will be printed at
the end:

```
Enclave Image successfully created.
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "d68be77c357668869010a6c56a7d2248e47128eb4aa19f4063bd3edafc075826873661a8dc0ce86321a3eb32274d093a",
...
  }
}
```

If you're using a Glove service and want to confirm it's genuine, build the same version of the enclave they are 
claiming to use and verify you get the same image measurement that's in the Glove attestation. A match proves they are
running a Glove enclave on genuine AWS Nitro hardware.

> [!NOTE]
> The enclave image measurement for the latest build is
> `d68be77c357668869010a6c56a7d2248e47128eb4aa19f4063bd3edafc075826873661a8dc0ce86321a3eb32274d093a`.

# Running Glove

If you want to run your own Glove service, you will need to have a compatible AWS EC2 instance with AWS Nitro Enclaves
enabled. You can follow the instructions [here](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html#launch-instance)
to provision the correct EC2 instance. Make sure to use x86-64, with the Nitro Enclaves option enabled.

Then install the [Nitro Enclaves CLI](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html).
Make sure to allocate at least 512 MiB for the enclave.

Make sure the `service` binary and the `glove.eif` files are in the same directory. If you built using `build.sh` they
will both be in `target/release`:

```shell
target/release/service --address=<LISTEN> --proxy-secret-phrase=<SECRET PHRASE> --node-endpoint=<URL>
```

To understand what these arguments mean and others, you will need to first read the help with `--help`.

You can check the enclave is running with:

```shell
nitro-cli describe-enclaves
```

If the enclave fails to start or you want to view its logs, start the service with `--enclave-mode=debug` which will 
start the enclave in debug mode and output to the console.

> [!WARNING]
> Debug mode is not secure and will be reflected in the enclave's remote attestation. Do not enable this in production.

# REST API

The Glove service exposes a REST API for submitting votes and interacting with it.

## `GET /info`

Get information about the Glove service, including the enclave. This can also act as a health check.

### Request

None

### Response

A JSON object with the following fields:

#### `proxy_account`

The Glove proxy account address. Users will need to first assign this account as their
[governance proxy](https://wiki.polkadot.network/docs/learn-proxies#proxy-types) before they can submit votes.

#### `network_name`

The substrate-based network the Glove service is connected to.

#### `node_endpoint`

The [node endpoint](https://wiki.polkadot.network/docs/maintain-endpoints) URL the service is using to interact with the
network. This is only provided as a convenience for Glove clients, otherwise they can use any node endpoint as long as
it points to the same network.

#### `attestation_bundle`

The attestation bundle of the enclave the service is using. This is a hex-encoded string (without the `0x` prefix),
representing the [`AttestationBundle`](common/src/attestation.rs#L43) struct in
[SCALE](https://docs.substrate.io/reference/scale-codec/) encoding. 

The attestation bundle is primarily used in Glove proofs when the enclave submits its mixed votes on-chain. It's
available here for clients to verify the enclave's identity before submitting any votes.

#### Example

```json
{
  "proxy_account": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
  "network_name": "rococo",
  "node_endpoint": "wss://rococo-rpc.polkadot.io",
  "attestation_bundle": "6408de7737c59c238890533af25896a2c20608d8b380bb01029acb3927..."
}
```

## `POST /vote`

Submit a signed vote request to be included in the Glove mixing process.

Multiple votes can be submitted for the same poll, but it's up to the discrection of the Glove service to accept them.
If they are accepted they will replace the previous vote for that poll.

### Request

A JSON object with the following fields:

#### `request`

[SCALE-encoded](https://docs.substrate.io/reference/scale-codec/) [`VoteRequest`](common/src/lib.rs#L36) struct as a 
hex string (without the `0x` prefix).

#### `signature`

[SCALE-encoded](https://docs.substrate.io/reference/scale-codec/)
[`MultiSignature`](https://docs.rs/sp-runtime/latest/sp_runtime/enum.MultiSignature.html) as a hex string (without the
`0x` prefix). Signed by`VoteRequest.account`, the signature is of the `VoteRequest` in SCALE-encoded bytes, i.e. the
`request` field without the hex-encoding.

#### Example

[This example](common/test-resources/vote-request-example.mjs) shows how to create a signed vote request JSON body using
the [Polkadot JS API](https://polkadot.js.org/docs). The request is made by the Bob dev account on the Rococo network
for a vote of aye, on poll 185, using 2.23 ROC at 2x conviction.

### Response

If the vote request was successfully received and accepted by the service then an empty response with `200 OK` status
code is returned. This does not mean, however, the vote was mixed and submitted on-chain; just that the Glove service
will do so at the appropriate time.

If there was something wrong with the vote request then a `400 Bad Request` is returned with a JSON object containing 
the error type (`error`) and description (`description`).

## `POST /remove-vote`

Submit a signed remove vote request for removing a previously submitted vote.

### Request

A JSON object with the following fields:

#### `request`

[SCALE-encoded](https://docs.substrate.io/reference/scale-codec/) [`RemoveVoteRequest`](client-interface/src/lib.rs#374)
struct as a hex string (without the `0x` prefix).

#### `signature`

[SCALE-encoded](https://docs.substrate.io/reference/scale-codec/)
[`MultiSignature`](https://docs.rs/sp-runtime/latest/sp_runtime/enum.MultiSignature.html) as a hex string (without the
`0x` prefix). Signed by`RemoveVoteRequest.account`, the signature is of the `RemoveVoteRequest` in SCALE-encoded bytes,
i.e. the `request` field without the hex-encoding.

### Response

An empty response with `200 OK` status code is returned if the previous vote was successfully removed or if there was
no matching vote.

If there was something wrong with the request itself then a `400 Bad Request` is returned with a JSON object containing
the error type (`error`) and description (`description`).

# Client CLI

There is a CLI client for interacting with the Glove service from the command line. It is built alonside the Glove
service and enclave with the `./build.sh` command (described above). To build it on a local machine:

```shell
cargo build --release --bin client
```

```shell
target/release/client --help
```

First join Glove with the `join-glove` command and then vote with `vote`.

# Development

## MacOS

If building on MacOS, then use `cargo` directly rather than the `./build.sh` script. Only mock mode will be available.

## Regenerating the Substrate metadata

You first need the `subxt-cli` tool installed:

```shell
cargo install subxt-cli
```

Then run this in the home directory of this project:

```shell
subxt metadata --url="wss://rpc.polkadot.io:443" -f bytes > assets/polkadot-metadata.scale
```
