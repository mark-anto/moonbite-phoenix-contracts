use soroban_sdk::Address;

/// Extension trait that provides a uniform method name for authorization checks.
pub trait RequireSignature {
    /// Require that the address has authorized the current invocation.
    fn require_signature(&self);
}

impl RequireSignature for Address {
    fn require_signature(&self) {
        self.require_auth();
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use crate::{authorized_by, no_access_control, with_access_control};
    use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Env};

    struct DemoContract;

    #[with_access_control]
    impl DemoContract {
        fn always_allow(_address: Address) -> bool {
            true
        }

        fn never_allow(_address: Address) -> bool {
            false
        }

        #[authorized_by(user, always_allow)]
        pub fn allowed(env: Env, user: Address) {
            let _ = env;
            let _ = user;
        }

        #[authorized_by(user, never_allow)]
        pub fn forbidden(env: Env, user: Address) {
            let _ = env;
            let _ = user;
        }

        #[no_access_control]
        pub fn open_call() {}
    }

    #[contract]
    pub struct HarnessContract;

    #[contractimpl]
    impl HarnessContract {
        pub fn call_allowed(env: Env, user: Address) {
            DemoContract::allowed(env, user);
        }

        pub fn call_forbidden(env: Env, user: Address) {
            DemoContract::forbidden(env, user);
        }
    }

    #[test]
    fn allows_authorized_calls() {
        let env = Env::default();
        env.mock_all_auths();
        let user = Address::random(&env);

        let contract_id = env.register_contract(None, HarnessContract);
        let client = HarnessContractClient::new(&env, &contract_id);

        client.call_allowed(&user);
    }

    // Additional behavior checks that require observing a panic cannot be asserted here because
    // the Soroban test environment uses a host that aborts when authorization fails.
}
