**Table of Contents**

- [Building Glove](#building-glove)
- [Verifying Glove votes](#verifying-glove-votes)
- [Glove mixing](#glove-mixing)
- [Running the Glove service](#running-the-glove-service)
- [REST API](#rest-api)
- [Deployment](#deployment)

# Building Glove

You will need an x86-64 machine with docker installed to fully build Glove:

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
    "PCR0": "609e2ce86435160b1aba2f1995bdab26c8ce0f3db0d81fb435166e22b6d95261cbee8ed046469b009d1048e614227cde",
...
  }
}
```

# Verifying Glove votes

If you're using a Glove service and want to confirm the on-chain vote was mixed from a genuine Glove enclave, run the
following command:

```shell
target/release/client --glove-url=<GLOVE SERVICE URL> verify-vote --account=<GLOVE CLIENT ACCOUNT> --poll-index=<POLL INDEX> --enclave-measurement=<EXPECTED ENCLAVE MEASUREMENT>
```

> [!NOTE]
> You can build just the client with `./build.sh client`.

This will perform the following checks:

* The Glove proxy account has voted on the given poll
* The on-chain vote comes accompanied with a valid signed Glove proof
* The Glove proof was produced by a genuine AWS Nitro enclave
* The proof mirrors the on-chain vote for the account

This is an example output of a successful verification:

```
Nonce was not provided so cannot check if most recent vote request was used by Glove proxy
Vote mixed by VERIFIED Glove enclave: Nay using 0.979 ROC with conviction None
```

> [!NOTE]
> The warning about the nonce can be resolved by providing the nonce of the vote request with the `--nonce` flag.

`--enclave-measurement` is the expected _audited_ Glove enclave identity. If this is not known then run the command
without it, and if the client determines the vote was mixed by a _potential_ Glove enclave it will print out
instructions on how to audit and verify the enclave code:

```
Nonce was not provided so cannot check if most recent vote request was used by Glove proxy
Vote mixed by POSSIBLE Glove enclave: Nay using 0.979 ROC with conviction None

To verify this is a Glove enclave, first audit the code:
git clone --depth 1 --branch v0.0.12 https://github.com/projectglove/glove-monorepo/

And then check 'PCR0' output is '0x609e2ce86435160b1aba2f1995bdab26c8ce0f3db0d81fb435166e22b6d95261cbee8ed046469b009d1048e614227cde' by running:
./build.sh
```

The `--branch` version that's printed is specific to the Glove proof for that vote (and not necessarily the 
current version of the Glove client or service), and building the enclave for that version should produce the 
expected `PCR0` measurement.

> [!NOTE]
> The client can also be used to submit vote requests. Run with `--help` to see full options.

# Glove mixing

These are the rules when comes to vote requests and mixing:

* The mixing of the vote requests always occurs inside the enclave, the code of which can be found
  [here](enclave/src/lib.rs).
* The mixing will be delayed as late as possible in the poll's timeline (details below). This is to prevent leakage 
  of information of the private vote requests, something which can happen if there are multiple mixes.
* This means there will only be one mixing event, and thus [vote requests](#post-vote) and
  [remove vote requests](#post-remove-vote) after the mix will be rejected.
* If the vote request returns with a success the service will include it in the mixing, even if it is the only
  request for that poll.
* The assigned netted vote balance will never be more than the balance in the original vote request.
* If one on the rare event all of the vote requests net to a balance of zero (i.e. neither aye or nay) then the 
  Glove vote will be abstain with a balance of one.
* If at the time of mixing an account has insufficient funds to cover their assigned vote balance, their vote will 
  be removed and mix attempted again.
* If a participant also votes on the same poll outside of Glove, their vote request will be removed. If the service has
  already mixed the votes then a re-mix will be attempted immediately. This is the only scenario where a poll will 
  be mixed more than once.

The Glove service will initiate a mxing of the vote requests for a poll when one of the following conditions are met:

* The poll reaches near the end of its decision period (but still enough time to mix and submit on-chain). There are 
  two scenarios:
  * The poll hasn't entered confirmation and is on its way to be rejected. The mixed votes will be submitted, even if 
    they are "nay" and only confirming the poll's rejection. This is necessary to show the Glove proxy is not
    withholding votes.
  * The poll is in confirmation. Even though the confirmation period will extend beyond the poll's decision period, 
    it's possible for a non-Glove voter to take it out of confirmation, and thus cause it to be rejected immediately.
    Thus the Glove service risks not being able to mix if it waits until the end of the confirmation period.
* The poll reaches near the end of its confirmation period **and** it's still within its decision period. Since the poll 
  is on course to be accepted if the confirmation period elapses, the Glove service will need to mix before then.

> [!WARNING]
> Testing and development can be difficult with this behaviour as decision periods can last days. To alleviate this, 
> the `--regular-mix` flag can turn this off and mix votes on a regular basis. However, this MUST NOT be enabled in 
> production as it will leak private information of the vote requests.

# Running the Glove service

If you want to run your own Glove service, you will need to have a compatible AWS EC2 instance with AWS Nitro Enclaves
enabled. You can follow the instructions [here](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html#launch-instance)
to provision the correct EC2 instance. Make sure to use x86-64, with the Nitro Enclaves option enabled.

Then install the [Nitro Enclaves CLI](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html).
Make sure to allocate at least 512 MiB for the enclave.

You will also need to create a DynamoDB table for the service. The table must have a sort key, and both partition and
sort keys must be strings. Make sure to attach an IAM role to the EC2 instance which gives it write access to the table.

Make sure the `service` binary and the `glove.eif` file are in the same directory. If you built using `build.sh` they
will both be in `target/release`:

```shell
target/release/service --address=<LISTEN> --proxy-secret-phrase=<SECRET PHRASE> --node-endpoint=<URL> --subscan-api-key=<API KEY> dynamodb --table-name=<GLOVE TABLE>
```

The service makes use of [Subscan](https://support.subscan.io/) and it is recommended an API key be provided, though 
not required.

Full documenation of the arguments, along with other flags, can be found with `--help`.

You can check the enclave is running with:

```shell
nitro-cli describe-enclaves
```

If the enclave fails to start or you want to view its logs, start the service with `--enclave-mode=debug` which will
start the enclave in debug mode and output to the console.

> [!WARNING]
> Debug mode is not secure and will be reflected in the enclave's remote attestation and any Glove proofs created. Do
> not enable this in production.

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

The substrate-based network the Glove service is connected to. This is a [SS58](https://github.com/paritytech/ss58-registry)
unique identifier.

#### `attestation_bundle`

The attestation bundle of the enclave the service is using. This is a hex string representing the
[`AttestationBundle`](common/src/attestation.rs#L38) struct in
[SCALE](https://docs.substrate.io/reference/scale-codec/) encoding.

The attestation bundle is primarily used in Glove proofs when the enclave submits its mixed votes on-chain. It's
available here for clients to verify the enclave's identity before submitting any votes.

#### `version`

The version of the Glove service.

#### Example

```json
{
  "proxy_account": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
  "network_name": "rococo",
  "attestation_bundle": "0x6408de7737c59c238890533af25896a2c20608d8b380bb01029acb3927...",
  "version": "0.0.8"
}
```

## `POST /vote`

Submit a signed vote request to be included in the Glove mixing process.

Multiple votes can be submitted for the same poll, but it's up to the discretion of the Glove service to accept them.
If they are accepted they will replace the previous vote for that poll.

### Request

A JSON object with the following fields:

#### `request`

[SCALE-encoded](https://docs.substrate.io/reference/scale-codec/) [`VoteRequest`](common/src/lib.rs#L57) as a
hex string.

#### `signature`

[SCALE-encoded](https://docs.substrate.io/reference/scale-codec/)
[`MultiSignature`](https://docs.rs/sp-runtime/latest/sp_runtime/enum.MultiSignature.html) as a hex string. The 
signature is of the `VoteRequest` in SCALE-encoded bytes, i.e. the `request` field without the hex-encoding, signed by
`VoteRequest.account`.

#### Example

[This example](common/test-resources/vote-request-example.mjs) shows how to create a signed vote request JSON body using
the [Polkadot JS API](https://polkadot.js.org/docs). The request is made by the Bob dev account on the Rococo network
for a vote of aye, on poll 185, using 2.23 ROC at 2x conviction.

### Response

If the vote request was successfully received and accepted by the service then an empty response with `200 OK` status
code is returned. This does not mean, however, the vote was mixed and submitted on-chain; just that the Glove service
will do so at the appropriate time.

If request body is invalid then a `422 Unprocessable Entity` is returned. If there was something wrong with the 
request itself then a `400 Bad Request` is returned with a JSON object containing the error type (`error`) and 
description (`description`). `429 Too Many Requests` can also be returned and the request should be retried later.

## `POST /remove-vote`

Submit a signed remove vote request for removing a previously submitted vote.

### Request

A JSON object with the following fields:

#### `request`

[SCALE-encoded](https://docs.substrate.io/reference/scale-codec/) [`RemoveVoteRequest`](client-interface/src/lib.rs#L416)
as a hex string.

#### `signature`

[SCALE-encoded](https://docs.substrate.io/reference/scale-codec/)
[`MultiSignature`](https://docs.rs/sp-runtime/latest/sp_runtime/enum.MultiSignature.html) as a hex string. The 
signature is of the `RemoveVoteRequest` in SCALE-encoded bytes, i.e. the `request` field without the hex-encoding, 
signed by `RemoveVoteRequest.account`,

### Response

An empty response with `200 OK` status code is returned if the previous vote was successfully removed or if there was
no matching vote.

If request body is invalid then a `422 Unprocessable Entity` is returned. If there was something wrong with the 
request itself then a `400 Bad Request` is returned with a JSON object containing the error type (`error`) and 
description (`description`). `429 Too Many Requests` can also be returned and the request should be retried later.

## `GET /poll-info/{poll_index}`

Get Glove-specific information about poll with index `poll_index`.

### Request

None

### Response

A JSON object with the following fields:

#### `mixing_time`

**Estimated** time the Glove service will mix vote requests and submit them on-chain. If the service hasn't received 
requests for this poll then this is the time the service _would_ mix if it had. This field is only available for polls
which have reached the decision phase. The mixing time isn't fixed and may change as the poll progresses. It is thus 
recommended to occasionally poll this end-point.

The time is given in terms of both block number and UNIX timestamp seconds; the value is an object with fields 
`block_number` and `timestamp`. 

If the poll is not active then `400 Bad Request` is returned.

#### Example

```json
{
  "mixing_time": {
    "block_number": 22508946,
    "timestamp": 1726170438
  }
}
```

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

# Deployment

This repo also has example configuration as code scripts for deployment of the Glove service, located in the
[devops](devops) directory. Cloud infrastructure is handled by Terraform/OpenTofu and VM configuration by Ansible.

## Terraform/OpenTofu
The scripts in the [terraform](devops/terraform) subfolder are responsible for deployment of:
- VM with Enclave,
- Application Load Balancer (ALB),
- DNS entries,
- SSL certificate for a test system,
- DynamoDB table,
- and matching Security Groups (SG) and IAM roles.

Please note, that in the test TLS traffic terminates on the load balancer, not VM.

## Ansible
In the [Ansible](devops/ansible) folder there is the glove role and the matching playbook with an inventory file for the test deployment.
The role gets the latest binaries from the github, release page, sets systemd service for glove API host and prepare Nitro enclave.

## GitHub Actions

The Ansible playbook and the role are used in the release GHA. Whenever a new git tag is pushed, the action builds the
binaries, and then uses Ansible to update the test deployment.

> [!IMPORTANT]  
> The git tag **must** begin with `v` and match the project version in [Cargo.toml](Cargo.toml). This is important to 
> ensure users download the correct version of the enclave code when verifying Glove proofs.

## Debugging

To check the status of the service run:
```
systemctl status glove
```

Glove service logs are picked up by SystemD and can be accessed with:

```
journalctl -u glove
```

or to follow the flow of logs:

```
journalctl -fu glove
```

or to get extra information on latest logs:

```
journalctl -xeu glove
```
