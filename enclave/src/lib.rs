use std::str::FromStr;

use bigdecimal::{BigDecimal, ToPrimitive};
use rand::distributions::{Distribution, Uniform};
use rand::thread_rng;

use common::MixedVotes;
use enclave_interface::SignedVoteRequest;

pub fn mix_votes(signed_requests: &Vec<SignedVoteRequest>) -> Option<MixedVotes> {
    let ayes_balance = signed_requests.iter().filter(|r| r.request.aye).map(|r| r.request.balance).sum::<u128>();
    let nays_balance = signed_requests.iter().filter(|r| !r.request.aye).map(|r| r.request.balance).sum::<u128>();
    let net_balance = ayes_balance.abs_diff(nays_balance);
    if net_balance == 0 {
        return None;
    }

    let mut rng = thread_rng();

    // Generate a random multiplier between 1x and 2x.
    let multipler_range = Uniform::from(1.0..2.0);
    let randomized_balances: Vec<BigDecimal> = signed_requests
        .iter()
        .map(|signed_request| {
            let random_multiplier = multipler_range.sample(&mut rng);
            let random_multiplier = BigDecimal::from_str(random_multiplier.to_string().as_str()).unwrap();
            random_multiplier * signed_request.request.balance
        })
        .collect();

    let total_randomized_balance = randomized_balances.iter().sum::<BigDecimal>();

    let mut net_balances: Vec<u128> = randomized_balances
        .iter()
        .enumerate()
        .map(|(index, randomized_balance)| {
            let weight = randomized_balance / &total_randomized_balance;
            // It's possible the randomized weights will lead to a value greater than the request
            // balance. This is more likely to happen if there are fewer requests and the random
            // multiplier is sufficiently relatively bigger than the others.
            (net_balance * weight).to_u128().unwrap().min(signed_requests[index].request.balance)
        })
        .collect();

    let mut leftover_balance = net_balance - net_balances.iter().sum::<u128>();

    let mut index: usize = 0;
    while leftover_balance > 0 {
        if signed_requests[index].request.balance > net_balances[index] {
            let balance_allowance = signed_requests[index].request.balance - net_balances[index];
            let assign_extra_balance = leftover_balance.min(balance_allowance);
            net_balances[index] += assign_extra_balance;
            leftover_balance -= assign_extra_balance;
        }
        index += 1;
    }

    Some(MixedVotes { aye: ayes_balance > nays_balance, balances: net_balances })
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
            mix_votes(&vec![vote_request(true, 1u128)]),
            Some(MixedVotes { aye: true, balances: vec![1u128] })
        );
    }

    #[test]
    fn two_equal_but_opposite_votes() {
        assert_eq!(
            mix_votes(&vec![
                vote_request(true, 10u128),
                vote_request(false, 10u128)
            ]),
            None
        );
    }

    #[test]
    fn two_aye_votes() {
        assert_eq!(
            mix_votes(&vec![
                vote_request(true, 10u128),
                vote_request(true, 5u128)
            ]),
            Some(MixedVotes { aye: true, balances: vec![10u128, 5u128] })
        );
    }

    #[test]
    fn two_nay_votes() {
        assert_eq!(
            mix_votes(&vec![
                vote_request(false, 5u128),
                vote_request(false, 10u128)
            ]),
            Some(MixedVotes { aye: false, balances: vec![5u128, 10u128] })
        );
    }

    #[test]
    fn aye_votes_bigger_than_nye_votes() {
        let requests = vec![
            vote_request(true, 30u128),
            vote_request(true, 20u128),
            vote_request(false, 26u128),
            vote_request(false, 4u128)
        ];
        let result = mix_votes(&requests).unwrap();
        assert_eq!(result.aye, true);
        assert_eq!(result.balances.len(), 4);
        assert_eq!(result.balances.iter().sum::<u128>(), 20u128);

        for (index, mixed_balance) in result.balances.iter().enumerate() {
            assert!(*mixed_balance <= requests[index].request.balance);
        }
        println!("{:?}", result)
    }

    #[test]
    fn aye_votes_smaller_than_nye_votes() {
        let requests = vec![
            vote_request(false, 32u128),
            vote_request(true, 15u128),
        ];
        let result = mix_votes(&requests).unwrap();
        assert_eq!(result.aye, false);
        assert_eq!(result.balances.len(), 2);
        assert_eq!(result.balances.iter().sum::<u128>(), 17u128);

        for (index, mixed_balance) in result.balances.iter().enumerate() {
            assert!(*mixed_balance <= requests[index].request.balance);
        }
    }

    #[test]
    fn leftovers() {
        let result = mix_votes(&vec![
            vote_request(false, 5u128),
            vote_request(true, 10u128)
        ]).unwrap();
        assert_eq!(result.balances.iter().sum::<u128>(), 5u128);
    }

    fn vote_request(aye: bool, balance: u128) -> SignedVoteRequest {
        SignedVoteRequest {
            request: VoteRequest::new(AccountId32::from([1; 32]), 0, aye, balance),
            signature: MultiSignature::Sr25519(sr25519::Signature::default())
        }
    }
}
