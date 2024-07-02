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
    "PCR0": "df7badf3a14d1a3b979ff00cd0e37e9cafd89da7a4b1379361bf309a4cdd92fa7f02f33cbb3cf317e7fcaa4881285673",
    "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
    "PCR2": "064632aaf6cdcfea926d7130dac648842831071aa3f077fce7fe6a5cf667535a170d62f142c3be953e73ac09a0d9ecda"
  }
}
```

If you're using a Glove service and want to confirm it's genuine, build the same version of the enclave they are 
claiming to use and verify you get the same image measurement that's in the Glove attestation. A match proves they are
running a Glove enclave on genuine AWS Nitro hardware.

> [!NOTE]
> The enclave image measurement for the latest build is
> `df7badf3a14d1a3b979ff00cd0e37e9cafd89da7a4b1379361bf309a4cdd92fa7f02f33cbb3cf317e7fcaa4881285673`.

# Running Glove

If you want to run your own Glove service, you will need to have a compatible AWS EC2 instance with AWS Nitro Enclaves
enabled. You can follow the instructions [here](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html#launch-instance)
to provision the correct EC2 instance. Make sure to use x86-64, with the Nitro Enclaves option enabled.

Then install the [Nitro Enclaves CLI](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html).
Make sure to allocate at least 512 MiB for the enclave.

Make sure the `service` binary and the `glove.eif` files are in the same directoy. If you built using `build.sh` they
will both be in `target/release`:

```shell
target/release/service --address=<LISTEN> --proxy-secret-phrase=<SECRET PHRASE> --network-url=<URL>
```

Run with `--help` to see example network endpoints for various chains.

You can check the enclave is running with:

```shell
nitro-cli describe-enclaves
```

If the enclave fails to start or you want to view its logs, start the service with `--enclave-mode=debug` which will 
start the enclave in debug mode and output to the console.

> [!WARNING]
> Debug mode is not secure and will be reflected in the enclave's remote attestation. Do not enable this in production.

## Client CLI

There is a CLI client for interacting with the Glove service from the command line:

```shell
target/release/client --help
```

First join Glove with the `join-glove` command and then vote with `vote`.

# Development

## MacOS

If building on MacOS, then use `cargo` directly rather than the build script. Only mock mode will be available.

## Regenerating the Substrate metadata

You first need the `subxt-cli` tool installed:

```shell
cargo install subxt-cli
```

Then run this in the home directory of this project:

```shell
subxt metadata --url="wss://rpc.polkadot.io:443" -f bytes > assets/polkadot-metadata.scale
```
