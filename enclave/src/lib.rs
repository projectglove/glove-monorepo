use std::str::FromStr;

use bigdecimal::{BigDecimal, ToPrimitive, Zero};
use rand::distributions::{Distribution, Uniform};
use rand::thread_rng;

use common::{AssignedBalance, MixedVotes};
use enclave_interface::SignedVoteRequest;

pub fn mix_votes(signed_requests: &Vec<SignedVoteRequest>) -> Option<MixedVotes> {
    let mut rng = thread_rng();
    // Generate a random multiplier between 1x and 2x.
    let multipler_range = Uniform::from(1.0..2.0);

    let mut ayes_balance = 0u128;
    let mut nays_balance = 0u128;
    let mut randomized_balances: Vec<BigDecimal> = Vec::new();
    let mut total_randomized_balance = BigDecimal::zero();

    for signed_request in signed_requests {
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
    if net_balance == 0 {
        return None;
    }

    let mut net_balances: Vec<u128> = signed_requests
        .iter()
        .zip(randomized_balances)
        .map(|(signed_request, randomized_balance)| {
            let weight = randomized_balance / &total_randomized_balance;
            // It's possible the randomized weights will lead to a value greater than the request
            // balance. This is more likely to happen if there are fewer requests and the random
            // multiplier is sufficiently bigger relative to the others.
            (net_balance * weight).to_u128().unwrap().min(signed_request.request.balance)
        })
        .collect();

    let mut leftover_balance = net_balance - net_balances.iter().sum::<u128>();

    let mut index = 0;
    while leftover_balance > 0 {
        if signed_requests[index].request.balance > net_balances[index] {
            let balance_allowance = signed_requests[index].request.balance - net_balances[index];
            let assign_extra_balance = leftover_balance.min(balance_allowance);
            net_balances[index] += assign_extra_balance;
            leftover_balance -= assign_extra_balance;
        }
        index += 1;
    }

    let assigned_balances = signed_requests
        .iter()
        .zip(net_balances)
        .map(|(signed_request, balance)| {
            AssignedBalance { nonce: signed_request.request.nonce, balance }
        })
        .collect::<Vec<_>>();
    Some(MixedVotes { aye: ayes_balance > nays_balance, assigned_balances })
}

#[cfg(test)]
mod tests {
    use sp_core::crypto::AccountId32;
    use sp_runtime::MultiSignature;
    use sp_runtime::testing::sr25519;

    use common::VoteRequest;

    use super::*;

    #[test]
    fn empty() {
        assert_eq!(mix_votes(&vec![]), None);
    }

    #[test]
    fn single() {
        assert_eq!(
            mix_votes(&vec![vote_request(1, true, 10)]),
            Some(MixedVotes { aye: true, assigned_balances: vec![assigned_balance(1, 10)] })
        );
    }

    #[test]
    fn two_equal_but_opposite_votes() {
        assert_eq!(
            mix_votes(&vec![
                vote_request(1, true, 10),
                vote_request(2, false, 10)
            ]),
            None
        );
    }

    #[test]
    fn two_aye_votes() {
        assert_eq!(
            mix_votes(&vec![
                vote_request(1, true, 10),
                vote_request(2, true, 5)
            ]),
            Some(MixedVotes {
                aye: true,
                assigned_balances: vec![assigned_balance(1, 10), assigned_balance(2, 5)]
            })
        );
    }

    #[test]
    fn two_nay_votes() {
        assert_eq!(
            mix_votes(&vec![
                vote_request(3, false, 5),
                vote_request(2, false, 10)
            ]),
            Some(MixedVotes {
                aye: false,
                assigned_balances: vec![assigned_balance(3, 5), assigned_balance(2, 10)]
            })
        );
    }

    #[test]
    fn aye_votes_bigger_than_nye_votes() {
        let signed_requests = vec![
            vote_request(3, true, 30),
            vote_request(7, true, 20),
            vote_request(1, false, 26),
            vote_request(4, false, 4)
        ];
        let result = mix_votes(&signed_requests).unwrap();
        println!("{:?}", result);

        let assigned_balances = result.assigned_balances;

        assert_eq!(result.aye, true);
        assert_eq!(assigned_balances.len(), 4);
        assert_eq!(assigned_balances.iter().map(|a| a.balance).sum::<u128>(), 20);
        assert(signed_requests, assigned_balances);
    }

    #[test]
    fn aye_votes_smaller_than_nye_votes() {
        let signed_requests = vec![
            vote_request(6, false, 32),
            vote_request(8, true, 15),
        ];
        let result = mix_votes(&signed_requests).unwrap();
        let assigned_balances = result.assigned_balances;

        assert_eq!(result.aye, false);
        assert_eq!(assigned_balances.len(), 2);
        assert_eq!(assigned_balances.iter().map(|a| a.balance).sum::<u128>(), 17);

        assert(signed_requests, assigned_balances);
    }

    #[test]
    fn leftovers() {
        let result = mix_votes(&vec![
            vote_request(4, false, 5),
            vote_request(2, true, 10)
        ]).unwrap();
        assert_eq!(result.assigned_balances.iter().map(|a| a.balance).sum::<u128>(), 5);
    }

    fn vote_request(nonce: u128, aye: bool, balance: u128) -> SignedVoteRequest {
        let request = VoteRequest {
            account: AccountId32::from([1; 32]),
            poll_index: 0,
            nonce,
            aye,
            balance
        };
        SignedVoteRequest {
            request,
            signature: MultiSignature::Sr25519(sr25519::Signature::default())
        }
    }

    fn assigned_balance(nonce: u128, balance: u128) -> AssignedBalance {
        AssignedBalance { nonce, balance }
    }

    fn assert(signed_requests: Vec<SignedVoteRequest>, assigned_balances: Vec<AssignedBalance>) {
        for (signed_request, assigned_balance) in signed_requests.iter().zip(assigned_balances) {
            assert_eq!(signed_request.request.nonce, assigned_balance.nonce);
            assert!(assigned_balance.balance <= signed_request.request.balance);
        }
    }
}
