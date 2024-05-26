use bigdecimal::{BigDecimal, ToPrimitive};

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
    balances: Vec<u128>
}

fn mix_votes(requests: &Vec<VoteMixRequest>) -> Option<VoteMixingResult> {
    let ayes_balance = requests.iter().filter(|r| r.aye).map(|r| r.balance).sum::<u128>();
    let nays_balance = requests.iter().filter(|r| !r.aye).map(|r| r.balance).sum::<u128>();
    let net_balance = ayes_balance.abs_diff(nays_balance);
    if net_balance == 0 {
        return None;
    }

    let total_balance = BigDecimal::from(ayes_balance + nays_balance);

    let mut net_balances: Vec<u128> = requests
        .iter()
        .map(|r| {
            let proportion = BigDecimal::from(r.balance) / total_balance.clone();
            (BigDecimal::from(net_balance) * proportion).to_u128().unwrap()
        })
        .collect();

    let mut leftover_balance = net_balance - net_balances.iter().sum::<u128>();

    let mut index: usize = 0;
    while leftover_balance > 0 {
        let balance_allowance = requests[index].balance - net_balances[index];
        if balance_allowance > 0 {
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
