use std::cmp::Ordering;
use std::collections::HashSet;
use std::str::FromStr;

use bigdecimal::{BigDecimal, ToPrimitive, Zero};
use rand::distributions::{Distribution, Uniform};
use rand::thread_rng;
use sp_core::H256;

use common::{AssignedBalance, GloveResult, SignedVoteRequest, VoteDirection};

pub fn mix_votes(
    genesis_hash: H256,
    signed_requests: &Vec<SignedVoteRequest>,
) -> Result<GloveResult, Error> {
    let poll_index = signed_requests
        .first()
        .ok_or(Error::Empty)?
        .request
        .poll_index;

    let mut rng = thread_rng();
    // Generate a random multiplier between 1x and 2x.
    let multipler_range = Uniform::from(1.0..2.0);

    let mut accounts = HashSet::new();
    let mut ayes_balance = 0u128;
    let mut nays_balance = 0u128;
    let mut randomized_balances: Vec<BigDecimal> = Vec::new();
    let mut total_randomized_balance = BigDecimal::zero();

    for signed_request in signed_requests {
        if signed_request.request.poll_index != poll_index {
            return Err(Error::MultiplePolls);
        }
        if !signed_request.verify() {
            return Err(Error::InvalidSignature);
        }
        if signed_request.request.genesis_hash != genesis_hash {
            return Err(Error::GensisHashMismatch);
        }
        if !accounts.insert(signed_request.request.account.clone()) {
            return Err(Error::DuplicateAccount);
        }
        let balance = signed_request.request.balance;
        if signed_request.request.aye {
            ayes_balance += balance;
        } else {
            nays_balance += balance;
        }
        let random_multiplier = multipler_range.sample(&mut rng);
        let random_multiplier = BigDecimal::from_str(&random_multiplier.to_string()).unwrap();
        let randomized_balance = random_multiplier * balance;
        randomized_balances.push(randomized_balance.clone());
        total_randomized_balance += randomized_balance;
    }

    let net_balance = ayes_balance.abs_diff(nays_balance);

    let net_balances = if net_balance == 0 {
        // TODO One token amount in the network decimals for the abstain balance
        vec![1; signed_requests.len()]
    } else {
        let mut net_balances = signed_requests
            .iter()
            .zip(randomized_balances)
            .map(|(signed_request, randomized_balance)| {
                let weight = randomized_balance / &total_randomized_balance;
                // It's possible the randomized weights will lead to a value greater than the request
                // balance. This is more likely to happen if there are fewer requests and the random
                // multiplier is sufficiently bigger relative to the others.
                (net_balance * weight)
                    .to_u128()
                    .unwrap()
                    .min(signed_request.request.balance)
            })
            .collect::<Vec<_>>();

        let mut leftover_balance = net_balance - net_balances.iter().sum::<u128>();

        let mut index = 0;
        while leftover_balance > 0 {
            if signed_requests[index].request.balance > net_balances[index] {
                let balance_allowance =
                    signed_requests[index].request.balance - net_balances[index];
                let assign_extra_balance = leftover_balance.min(balance_allowance);
                net_balances[index] += assign_extra_balance;
                leftover_balance -= assign_extra_balance;
            }
            index += 1;
        }

        net_balances
    };

    let assigned_balances = signed_requests
        .iter()
        .zip(net_balances)
        .map(|(signed_request, balance)| AssignedBalance {
            account: signed_request.request.account.clone(),
            nonce: signed_request.request.nonce,
            balance,
            conviction: signed_request.request.conviction,
        })
        .collect::<Vec<_>>();

    Ok(GloveResult {
        poll_index,
        direction: match ayes_balance.cmp(&nays_balance) {
            Ordering::Greater => VoteDirection::Aye,
            Ordering::Less => VoteDirection::Nay,
            Ordering::Equal => VoteDirection::Abstain,
        },
        assigned_balances,
    })
}

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq)]
pub enum Error {
    #[error("Empty vote requests")]
    Empty,
    #[error("Vote requests are for multiple polls")]
    MultiplePolls,
    #[error("Signature on a signed vote request is not valid")]
    InvalidSignature,
    #[error("Genesis hash on a vote request doesn't match expected value")]
    GensisHashMismatch,
    #[error("Duplicate account in vote requests")]
    DuplicateAccount,
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::Encode;
    use sp_core::{ed25519, Pair};
    use sp_runtime::MultiSignature;

    use common::Conviction::{Locked1x, Locked3x, Locked5x};
    use common::{Conviction, VoteRequest};
    use Conviction::Locked6x;

    use super::*;

    const GENESIS_HASH: H256 = H256::zero();
    const POLL_INDEX: u32 = 1;

    #[test]
    fn empty() {
        assert_eq!(mix_votes(GENESIS_HASH, &vec![]), Err(Error::Empty));
    }

    #[test]
    fn single() {
        let signed_requests = vec![vote(434, true, 10, Locked6x)];
        assert_eq!(
            mix_votes(GENESIS_HASH, &signed_requests),
            Ok(GloveResult {
                poll_index: POLL_INDEX,
                direction: VoteDirection::Aye,
                assigned_balances: vec![assigned(&signed_requests[0], 10)]
            })
        );
    }

    #[test]
    fn two_equal_but_opposite_votes() {
        let signed_requests = vec![
            vote(4, true, 10, Locked5x),
            vote(7, false, 10, Conviction::None),
        ];
        assert_eq!(
            mix_votes(GENESIS_HASH, &signed_requests),
            Ok(GloveResult {
                poll_index: POLL_INDEX,
                direction: VoteDirection::Abstain,
                assigned_balances: vec![
                    assigned(&signed_requests[0], 1),
                    assigned(&signed_requests[1], 1)
                ]
            })
        )
    }

    #[test]
    fn two_aye_votes() {
        let signed_requests = vec![vote(1, true, 10, Locked1x), vote(2, true, 5, Locked1x)];
        assert_eq!(
            mix_votes(GENESIS_HASH, &signed_requests),
            Ok(GloveResult {
                poll_index: POLL_INDEX,
                direction: VoteDirection::Aye,
                assigned_balances: vec![
                    assigned(&signed_requests[0], 10),
                    assigned(&signed_requests[1], 5)
                ]
            })
        );
    }

    #[test]
    fn two_nay_votes() {
        let signed_requests = vec![vote(3, false, 5, Locked3x), vote(2, false, 10, Locked1x)];
        assert_eq!(
            mix_votes(GENESIS_HASH, &signed_requests),
            Ok(GloveResult {
                poll_index: POLL_INDEX,
                direction: VoteDirection::Nay,
                assigned_balances: vec![
                    assigned(&signed_requests[0], 5),
                    assigned(&signed_requests[1], 10)
                ]
            })
        );
    }

    #[test]
    fn aye_votes_bigger_than_nye_votes() {
        let signed_requests = vec![
            vote(3, true, 30, Locked3x),
            vote(7, true, 20, Locked5x),
            vote(1, false, 26, Conviction::None),
            vote(4, false, 4, Locked6x),
        ];
        let result = mix_votes(GENESIS_HASH, &signed_requests).unwrap();
        println!("{:?}", result);

        assert_eq!(result.direction, VoteDirection::Aye);
        assert_eq!(result.assigned_balances.len(), 4);
        assert_eq!(
            result
                .assigned_balances
                .iter()
                .map(|a| a.balance)
                .sum::<u128>(),
            20
        );
        assert(signed_requests, result.assigned_balances);
    }

    #[test]
    fn aye_votes_smaller_than_nye_votes() {
        let signed_requests = vec![vote(6, false, 32, Locked1x), vote(8, true, 15, Locked3x)];
        let result = mix_votes(GENESIS_HASH, &signed_requests).unwrap();

        assert_eq!(result.direction, VoteDirection::Nay);
        assert_eq!(result.assigned_balances.len(), 2);
        assert_eq!(
            result
                .assigned_balances
                .iter()
                .map(|a| a.balance)
                .sum::<u128>(),
            17
        );
        assert(signed_requests, result.assigned_balances);
    }

    #[test]
    fn leftovers() {
        let result = mix_votes(
            GENESIS_HASH,
            &vec![vote(4, false, 5, Locked1x), vote(2, true, 10, Locked1x)],
        )
        .unwrap();
        assert_eq!(
            result
                .assigned_balances
                .iter()
                .map(|a| a.balance)
                .sum::<u128>(),
            5
        );
    }

    #[test]
    fn multiple_polls() {
        assert_eq!(
            mix_votes(
                GENESIS_HASH,
                &vec![
                    custom_vote(
                        ed25519::Pair::generate().0,
                        GENESIS_HASH,
                        1,
                        432,
                        true,
                        10,
                        Locked1x
                    ),
                    custom_vote(
                        ed25519::Pair::generate().0,
                        GENESIS_HASH,
                        2,
                        431,
                        false,
                        10,
                        Locked3x
                    )
                ]
            ),
            Err(Error::MultiplePolls)
        );
    }

    #[test]
    fn invalid_signature() {
        let signed_request = vote(1, true, 10, Locked1x);
        let mut invalid_signed_request = signed_request.clone();
        invalid_signed_request.signature =
            MultiSignature::Ed25519(ed25519::Signature::from([1; 64]));

        assert_eq!(
            mix_votes(GENESIS_HASH, &vec![invalid_signed_request]),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn genesis_hash_mismatch() {
        assert_eq!(
            mix_votes(H256::from([1; 32]), &vec![vote(434, true, 10, Locked6x)]),
            Err(Error::GensisHashMismatch)
        );
    }

    #[test]
    fn duplicate_account() {
        let (signing_key, _) = ed25519::Pair::generate();
        assert_eq!(
            mix_votes(
                GENESIS_HASH,
                &vec![
                    custom_vote(signing_key, GENESIS_HASH, 1, 432, true, 10, Locked1x),
                    custom_vote(signing_key, GENESIS_HASH, 1, 431, false, 10, Locked3x)
                ]
            ),
            Err(Error::DuplicateAccount)
        );
    }

    fn vote(nonce: u32, aye: bool, balance: u128, conviction: Conviction) -> SignedVoteRequest {
        let (signing_key, _) = ed25519::Pair::generate();
        custom_vote(
            signing_key,
            GENESIS_HASH,
            POLL_INDEX,
            nonce,
            aye,
            balance,
            conviction,
        )
    }

    fn custom_vote(
        signing_key: ed25519::Pair,
        genesis_hash: H256,
        poll_index: u32,
        nonce: u32,
        aye: bool,
        balance: u128,
        conviction: Conviction,
    ) -> SignedVoteRequest {
        let request = VoteRequest {
            account: signing_key.public().into(),
            genesis_hash,
            poll_index,
            nonce,
            aye,
            balance,
            conviction,
        };
        let signature = MultiSignature::Ed25519(signing_key.sign(&request.encode()));
        SignedVoteRequest { request, signature }
    }

    fn assigned(signed_request: &SignedVoteRequest, balance: u128) -> AssignedBalance {
        AssignedBalance {
            account: signed_request.request.account.clone(),
            nonce: signed_request.request.nonce,
            balance,
            conviction: signed_request.request.conviction,
        }
    }

    fn assert(signed_requests: Vec<SignedVoteRequest>, assigned_balances: Vec<AssignedBalance>) {
        for (signed_request, assigned_balance) in signed_requests.iter().zip(assigned_balances) {
            assert_eq!(signed_request.request.nonce, assigned_balance.nonce);
            assert!(assigned_balance.balance <= signed_request.request.balance);
        }
    }
}
