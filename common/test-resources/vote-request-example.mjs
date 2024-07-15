// Requires node version 21.7.3

import {ApiPromise, Keyring, WsProvider} from '@polkadot/api';
import {randomBytes} from 'crypto';

async function main () {
    const api = await ApiPromise.create({
        provider: new WsProvider('wss://rococo-rpc.polkadot.io'),
        // Register the Glove types
        types: {
            VoteRequest: {
                "account": "AccountId32",
                "genesis_hash": "H256",
                "poll_index": "Compact<u32>",
                "nonce": "u32",
                "aye": "bool",
                "balance": "u128",
                "conviction": "Conviction"
            },
            Conviction: {
                "_enum": {
                    "None": null,
                    "Locked1x": null,
                    "Locked2x": null,
                    "Locked3x": null,
                    "Locked4x": null,
                    "Locked5x": null,
                    "Locked6x": null
                }
            }
        }
    });

    const keyring = new Keyring({ type: 'sr25519' });
    const bob = keyring.addFromUri('//Bob', { name: 'Bob' });

    // Generate a random nonce
    const nonce = randomBytes(4).readUint32BE(0);

    const voteRequest = api.createType('VoteRequest', {
        account: bob.address,
        genesis_hash: api.genesisHash,
        poll_index: 185,
        nonce: nonce,
        aye: true,
        // Use the decimal information from the chain to convert to Planck units
        balance: 2.23 * Math.pow(10, api.registry.chainDecimals[0]),
        conviction: 'Locked2x'
    });

    const signature = bob.sign(voteRequest.toU8a(), { withType: true });

    const signedVoteRequest = {
        request: Buffer.from(voteRequest.toU8a()).toString('hex'),
        signature: Buffer.from(signature).toString('hex')
    };

    console.log(JSON.stringify(signedVoteRequest, null, 2));
}

main().catch(console.error).finally(() => process.exit());
