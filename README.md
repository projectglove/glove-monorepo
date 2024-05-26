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

* Basic implementation as a command line tool where voting requests are input from the command line and stored in-memory,
  and a "mix" command runs through a basic mixing algo and outputs the votes which then submitted on-chain.
* Signed voting requests. Using SCALE encoding seems to make most sense 
* Web server (use Rocket?). REST API will have to be something like:
  
   ```
   POST /submit-vote
   
   {
     "vote": <base64 binary>
     "signature": <base64 binary>
   }
   ```
  
* Vote mixing algo
* Signed Glove proof, again using SCALE encoding
* AWS Nitro enclave
* Persist voting requests
* Restoring state on startup from private store and on-chain
* When does the mixing occur? Is it configurable?
* Remove vote request from client
* Remove on-chain votes due to error conditions detected by the proxy
* Split votes
* Abstain votes?
* 
