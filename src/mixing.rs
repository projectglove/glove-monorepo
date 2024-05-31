use std::str::FromStr;

use bigdecimal::{BigDecimal, ToPrimitive};
use rand::distributions::{Distribution, Uniform};
use rand::thread_rng;

#[derive(Debug)]
struct VoteMixRequest {
    aye: bool,
    balance: u128
}

impl VoteMixRequest {
    fn new(aye: bool, balance: u128) -> Self {
        Self { aye, balance }
    }
}

#[derive(Debug, PartialEq)]
struct VoteMixingResult {
    aye: bool,
    /// The randomized mixed balance for the request at the same index. Note, it's possible for the
    /// value to be zero.
    balances: Vec<u128>
}

fn mix_votes(requests: &Vec<VoteMixRequest>) -> Option<VoteMixingResult> {
    let ayes_balance = requests.iter().filter(|r| r.aye).map(|r| r.balance).sum::<u128>();
    let nays_balance = requests.iter().filter(|r| !r.aye).map(|r| r.balance).sum::<u128>();
    let net_balance = ayes_balance.abs_diff(nays_balance);
    if net_balance == 0 {
        return None;
    }

    let mut rng = thread_rng();

    // Generate a random multiplier between 1x and 2x.
    let multipler_range = Uniform::from(1.0..2.0);
    let randomized_balances: Vec<BigDecimal> = requests
        .iter()
        .map(|request| {
            let random_multiplier = multipler_range.sample(&mut rng);
            let random_multiplier = BigDecimal::from_str(random_multiplier.to_string().as_str()).unwrap();
            random_multiplier * request.balance
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
            (net_balance * weight).to_u128().unwrap().min(requests[index].balance)
        })
        .collect();

    let mut leftover_balance = net_balance - net_balances.iter().sum::<u128>();

    let mut index: usize = 0;
    while leftover_balance > 0 {
        if requests[index].balance > net_balances[index] {
            let balance_allowance = requests[index].balance - net_balances[index];
            let assign_extra_balance = leftover_balance.min(balance_allowance);
            net_balances[index] += assign_extra_balance;
            leftover_balance -= assign_extra_balance;
        }
        index += 1;
    }

    Some(VoteMixingResult { aye: ayes_balance > nays_balance, balances: net_balances })
}

mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(mix_votes(&vec![]), None);
    }

    #[test]
    fn single() {
        assert_eq!(
            mix_votes(&vec![VoteMixRequest::new(true, 1u128)]),
            Some(VoteMixingResult { aye: true, balances: vec![1u128] })
        );
    }

    #[test]
    fn two_equal_but_opposite_votes() {
        assert_eq!(
            mix_votes(&vec![
                VoteMixRequest::new(true, 10u128),
                VoteMixRequest::new(false, 10u128)
            ]),
            None
        );
    }

    #[test]
    fn two_aye_votes() {
        assert_eq!(
            mix_votes(&vec![
                VoteMixRequest::new(true, 10u128),
                VoteMixRequest::new(true, 5u128)
            ]),
            Some(VoteMixingResult { aye: true, balances: vec![10u128, 5u128] })
        );
    }

    #[test]
    fn two_nay_votes() {
        assert_eq!(
            mix_votes(&vec![
                VoteMixRequest::new(false, 5u128),
                VoteMixRequest::new(false, 10u128)
            ]),
            Some(VoteMixingResult { aye: false, balances: vec![5u128, 10u128] })
        );
    }

    #[test]
    fn aye_votes_bigger_than_nye_votes() {
        let requests = vec![
            VoteMixRequest::new(true, 30u128),
            VoteMixRequest::new(true, 20u128),
            VoteMixRequest::new(false, 26u128),
            VoteMixRequest::new(false, 4u128)
        ];
        let result = mix_votes(&requests).unwrap();
        assert_eq!(result.aye, true);
        assert_eq!(result.balances.len(), 4);
        assert_eq!(result.balances.iter().sum::<u128>(), 20u128);

        for (index, mixed_balance) in result.balances.iter().enumerate() {
            assert!(*mixed_balance <= requests[index].balance);
        }
        println!("{:?}", result)
    }

    #[test]
    fn aye_votes_smaller_than_nye_votes() {
        let requests = vec![
            VoteMixRequest::new(false, 32u128),
            VoteMixRequest::new(true, 15u128),
        ];
        let result = mix_votes(&requests).unwrap();
        assert_eq!(result.aye, false);
        assert_eq!(result.balances.len(), 2);
        assert_eq!(result.balances.iter().sum::<u128>(), 17u128);

        for (index, mixed_balance) in result.balances.iter().enumerate() {
            assert!(*mixed_balance <= requests[index].balance);
        }
    }

    #[test]
    fn leftovers() {
        let result = mix_votes(&vec![
            VoteMixRequest::new(false, 5u128),
            VoteMixRequest::new(true, 10u128)
        ]).unwrap();
        assert_eq!(result.balances.iter().sum::<u128>(), 5u128);
    }
}
