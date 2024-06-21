# Running Glove

If you want to run your own Glove service, you will need to have a compatible AWS EC2 instance with AWS Nitro Enclaves
enabled. You can follow the instructions [here](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html#launch-instance)
to provision the correct EC2 instance. These instructions assume Amazon Linux 2023 on x86_64. Make sure Nitro Enclaves
are enabled.

Then install the [Nitro Enclaves CLI](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html).
Make sure to allocate at least 1024 MiB for the enclave.

Install the build tools:

```shell
sudo yum update -y
sudo yum groupinstall "Development Tools" -y
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Log out and back in again.

Build the service binary and enclave image:

```shell
./build-service-enclave.sh
```

```
Enclave Image successfully created.
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "10efc98b669b9ec152d4c03872ed904565bd5a3bc77b308ccb117c36f4d8cfed3929cf22a9a087ae964e46e9f15a175d",
    "PCR1": "52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546",
    "PCR2": "88e5121ee03f42b5e1a542210f5e8938459508a3b3bcb33cd39f85b97ea1888d2bf2725ad186fb43c53f31d6edd089a4"
  }
}
```

Take note of the `PCR0` value, which is a measurement of the enclave image.

Start the service, which will also start the enclave and connect to it. Killing the service will terminate the enclave.

```shell
target/release/service --proxy-secret-phrase=<SECRET PHRASE> --network-url=<URL>
```

Run with `--help` to see example network endpoints for various chains.

For now the service is hard-coded to listen on `localhost:8080`, which will be fixed.

You can check the enclave is running with:

```shell
nitro-cli describe-enclaves
```

If the enclave fails to start or you want to view its logs, start the service with `--enclave-mode=debug` which will 
start the enclave in debug mode and output to the console.

> [!WARNING]
> Debug mode is not secure and will be reflected in the enclave's remote attestation. Do not enable this in production.

Building the client CLI:

```shell
sudo yum install openssl-devel -y
```

```shell
cargo build -p client --release
```

There is a CLI client for interacting with the Glove service from the command line:

```shell
target/release/client --help
```

First join Glove with the `join-glove` command and then vote with `vote`.

# Development

## Regenerating the Substrate metadata

You first need the `subxt-cli` tool installed:

```shell
cargo install subxt-cli
```

Then run this in the home directory of this project:

```shell
subxt metadata --url="wss://rpc.polkadot.io:443" -f bytes > assets/polkadot-metadata.scale
```

## Things to do

* Sign the enclave image
* Signed Glove proof, again using SCALE encoding
* Persist voting requests
* Restoring state on startup from private store and on-chain
* When does the mixing occur? Is it configurable?
* Remove on-chain votes due to error conditions detected by the proxy
* Split votes
* Abstain votes?
