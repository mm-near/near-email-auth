use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{env, near_bindgen, AccountId, Balance, PanicOnDefault, Promise, PublicKey};

// Define the contract structure
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct Contract {
    owner_id: AccountId,
}

// Implement the contract structure
#[near_bindgen]
impl Contract {
    #[init]
    pub fn new_contract(owner_id: AccountId) -> Self {
        Self { owner_id }
    }

    pub fn add_key(self, public_key: PublicKey) {
        assert!(env::predecessor_account_id() == self.owner_id);
        Promise::new(env::current_account_id()).add_full_access_key(public_key);
    }

    pub fn delete_key(self, public_key: PublicKey) {
        assert!(env::predecessor_account_id() == self.owner_id);
        Promise::new(env::current_account_id()).delete_key(public_key);
    }

    pub fn transfer(self, to: AccountId, amount: Balance) {
        assert!(env::predecessor_account_id() == self.owner_id);
        Promise::new(to).transfer(amount);
    }
}
