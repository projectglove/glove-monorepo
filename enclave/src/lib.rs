use std::cmp::Ordering;
use std::collections::HashSet;
use std::str::FromStr;

use bigdecimal::{BigDecimal, ToPrimitive, Zero};
use rand::distributions::{Distribution, Uniform};
use rand::thread_rng;
use sp_core::H256;

use common::{AssignedBalance, Conviction, GloveResult, SignedVoteRequest, VoteDirection, VoteRequest};
use Error::Overflow;

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
    let mut aye_voting_power = 0u128;
    let mut nay_voting_power = 0u128;
    let mut voting_powers = Vec::<VotingPower>::new();
    let mut total_randomized_voting_power = BigDecimal::zero();

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
        let voting_power = VotingPower::try_from(
            &signed_request.request,
            multipler_range.sample(&mut rng)
        )?;
        if signed_request.request.aye {
            aye_voting_power = aye_voting_power.checked_add(voting_power.base).ok_or(Overflow)?;
        } else {
            nay_voting_power = nay_voting_power.checked_add(voting_power.base).ok_or(Overflow)?;
        }
        total_randomized_voting_power += &voting_power.randomized;
        voting_powers.push(voting_power);
    }

    let total_net_voting_power = aye_voting_power.abs_diff(nay_voting_power);

    let net_balances = if total_net_voting_power == 0 {
        // TODO One token amount in the network decimals for the abstain balance
        vec![1; signed_requests.len()]
    } else {
        let mut net_voting_powers = Vec::<u128>::new();
        let mut remaining_net_voting_power = total_net_voting_power;
        for voting_power in &voting_powers {
            let randomized_weight = &voting_power.randomized / &total_randomized_voting_power;
            // It's possible the randomized weights will lead to a value greater than the request
            // balance. This is more likely to happen if there are fewer requests and the random
            // multiplier is sufficiently bigger relative to the others.
            let net_voting_power = (total_net_voting_power * randomized_weight)
                .to_u128()
                .ok_or(Overflow)?
                .min(voting_power.base);
            remaining_net_voting_power = remaining_net_voting_power.saturating_sub(net_voting_power);
            net_voting_powers.push(net_voting_power);
        }

        for index in 0..net_voting_powers.len() {
            let base_voting_power = &voting_powers[index].base;
            let net_voting_power = net_voting_powers[index];
            let topup = remaining_net_voting_power.min(base_voting_power - net_voting_power);
            net_voting_powers[index] += topup;
            remaining_net_voting_power -= topup;
        }

        let mut net_balances = Vec::<u128>::new();
        for (net_voting_power, signed_request) in net_voting_powers.iter().zip(signed_requests) {
            net_balances.push(to_balance(*net_voting_power, signed_request.request.conviction)?);
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
        direction: match aye_voting_power.cmp(&nay_voting_power) {
            Ordering::Greater => VoteDirection::Aye,
            Ordering::Less => VoteDirection::Nay,
            Ordering::Equal => VoteDirection::Abstain,
        },
        assigned_balances,
    })
}

fn to_voting_power(balance: u128, conviction: Conviction) -> Result<u128, Error> {
    match conviction {
        Conviction::None => Some(balance / 10),
        Conviction::Locked1x => Some(balance),
        Conviction::Locked2x => balance.checked_mul(2),
        Conviction::Locked3x => balance.checked_mul(3),
        Conviction::Locked4x => balance.checked_mul(4),
        Conviction::Locked5x => balance.checked_mul(5),
        Conviction::Locked6x => balance.checked_mul(6),
    }.ok_or(Overflow)
}

fn to_balance(voting_power: u128, conviction: Conviction) -> Result<u128, Error> {
    match conviction {
        Conviction::None => voting_power.checked_mul(10).ok_or(Overflow),
        Conviction::Locked1x => Ok(voting_power),
        Conviction::Locked2x => Ok(voting_power / 2),
        Conviction::Locked3x => Ok(voting_power / 3),
        Conviction::Locked4x => Ok(voting_power / 4),
        Conviction::Locked5x => Ok(voting_power / 5),
        Conviction::Locked6x => Ok(voting_power / 6),
    }
}

struct VotingPower {
    base: u128,
    randomized: BigDecimal
}

impl VotingPower {
    fn try_from(request: &VoteRequest, random_multiplier: f64) -> Result<Self, Error> {
        let base = to_voting_power(request.balance, request.conviction)?;
        let randomized = base * BigDecimal::from_str(&random_multiplier.to_string()).unwrap();
        Ok(Self { base, randomized })
    }
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
    #[error("Arthmetic overflow in mixing calculation")]
    Overflow
}

#[cfg(test)]
mod tests {
    use parity_scale_codec::Encode;
    use sp_core::{ed25519, Pair};
    use sp_runtime::MultiSignature;

    use common::Conviction::{Locked1x, Locked2x, Locked3x, Locked5x};
    use common::{Conviction, VoteRequest};
    use Conviction::{Locked4x, Locked6x};

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
        mix_votes_and_check(signed_requests, VoteDirection::Aye, 60);
    }

    #[test]
    fn two_votes_with_equal_but_opposite_voting_powers() {
        let signed_requests = vec![
            vote(4, true, 10, Locked5x),   // 10 * 5 = 50
            vote(7, false, 25, Locked2x),  // 25 * 2 = 50
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
        mix_votes_and_check(signed_requests, VoteDirection::Aye, 15);
    }

    #[test]
    fn two_nay_votes() {
        let signed_requests = vec![vote(3, false, 5, Locked3x), vote(2, false, 10, Locked1x)];
        mix_votes_and_check(signed_requests, VoteDirection::Nay, 25);
    }

    #[test]
    fn aye_voting_power_bigger_than_nay_voting_power() {
        let signed_requests = vec![
            vote(3, true, 3000, Locked3x),           // 3000 * 3 = 9000
            vote(7, true, 2000, Locked5x),           // 2000 * 5 = 10000
            vote(1, false, 5000, Conviction::None),  // 5000 * 0.1 = 500
            vote(4, false, 400, Locked6x),           // 400 * 6 = 2400
        ];
        mix_votes_and_check(signed_requests, VoteDirection::Aye, 16100);
    }

    #[test]
    fn aye_voting_power_smaller_than_nay_voting_power() {
        let signed_requests = vec![
            vote(6, false, 10, Locked5x),  // 10 * 5 = 50
            vote(8, true, 45, Locked1x)    // 45 * 1 = 45
        ];
        mix_votes_and_check(signed_requests, VoteDirection::Nay, 5);
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

    fn mix_votes_and_check(
        signed_requests: Vec<SignedVoteRequest>,
        expected_direction: VoteDirection,
        expected_net_voting_power: u128,
    ) {
        let glove_result = mix_votes(GENESIS_HASH, &signed_requests).unwrap();
        println!("{:#?}", glove_result);

        assert_eq!(glove_result.poll_index, POLL_INDEX);
        assert_eq!(glove_result.direction, expected_direction);
        assert_eq!(glove_result.assigned_balances.len(), signed_requests.len());

        for (sr, ab) in signed_requests.iter().zip(&glove_result.assigned_balances) {
            assert_eq!(sr.request.nonce, ab.nonce);
            assert!(ab.balance <= sr.request.balance);
        }

        let actual_net_voting_power = glove_result
            .assigned_balances
            .iter()
            .map(|ab| to_voting_power(ab.balance, ab.conviction).unwrap())
            .sum::<u128>();
        assert!(actual_net_voting_power <= expected_net_voting_power);

        let voting_power_shortfall = expected_net_voting_power - actual_net_voting_power;
        // For any mixing request of size N, the maximum shortfall in the voting power that can
        // occur is 5N. This is not an issue as it's negligibly small compared to the Plank
        // multiplier (e.g. 10^10 for DOT).
        let max_possible_shortfall_due_to_integer_division = glove_result
            .assigned_balances
            .iter()
            .map(|ab| match ab.conviction {
                Conviction::None => 0,
                Locked1x => 0,
                Locked2x => 1,
                Locked3x => 2,
                Locked4x => 3,
                Locked5x => 4,
                Locked6x => 5,
            })
            .sum::<u128>();
        assert!(voting_power_shortfall <= max_possible_shortfall_due_to_integer_division);
    }
}
