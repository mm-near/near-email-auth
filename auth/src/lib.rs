use mailparse::{addrparse_header, parse_mail, MailHeaderMap};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{env, near_bindgen, Balance, Gas, GasWeight, PanicOnDefault, Promise};
use std::collections::HashMap;

use cfdkim::verify_email_with_resolver;

// Define the contract structure
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct AuthManager {}

const MIN_STORAGE: Balance = 11_100_000_000_000_000_000_000_000; //11.1Ⓝ
const WORKER_CODE: &[u8] = include_bytes!("worker.wasm");

#[derive(Debug, PartialEq)]
pub enum CommandEnum {
    Init,
    AddKey(String),
    DeleteKey,
    Transfer,
}

// Implement the contract structure
#[near_bindgen]
impl AuthManager {
    #[init]
    pub fn new_contract() -> Self {
        Self {}
    }

    fn create_new_subaccount(prefix: String) {
        let account_id = prefix + "." + &env::current_account_id().to_string();
        Promise::new(account_id.parse().unwrap())
            .create_account()
            .transfer(MIN_STORAGE)
            .deploy_contract(WORKER_CODE.to_vec());
    }

    fn add_key(prefix: String, key: String) {
        let account_id = prefix + "." + &env::current_account_id().to_string();
        Promise::new(account_id.parse().unwrap()).function_call_weight(
            "add_key".to_owned(),
            format!("{{\"public_key\": \"{}\"}}", key)
                .try_to_vec()
                .unwrap(),
            0,
            Gas(1000_000),
            GasWeight(1),
        );
    }

    fn verify_email(full_email: &[u8]) -> (String, String) {
        let email = parse_mail(full_email).unwrap();
        let logger = &slog::Logger::root(slog::Discard, slog::o!());
        //let resolver = Arc::new(MockResolver::new());
        let mut resolver: HashMap<String, String> = HashMap::new();
        resolver.insert(
            "20210112._domainkey.gmail.com".to_owned(), "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq8JxVBMLHZRj1WvIMSHApRY3DraE/EiFiR6IMAlDq9GAnrVy0tDQyBND1G8+1fy5RwssQ9DgfNe7rImwxabWfWxJ1LSmo/DzEdOHOJNQiP/nw7MdmGu+R9hEvBeGRQ Amn1jkO46KIw/p2lGvmPSe3+AVD+XyaXZ4vJGTZKFUCnoctAVUyHjSDT7KnEsaiND2rVsDvyisJUAH+EyRfmHSBwfJVHAdJ9oD8cn9NjIun/EHLSIwhCxXmLJlaJeNAFtcGeD2aRGbHaS7M6aTFP+qk4f2ucRx31cyCxbu50CDVfU+d4JkIDNBFDiV+MIpaDFXIf11bGoS08oBBQiyPXgX0wIDAQAB".to_owned());
        resolver.insert(
            "google._domainkey.near.org".to_owned(), "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvp9AC5ykeX9XfNDcv3lKLft21MpXUTb45fOvSyjArMjmVCJT8mQCkehardajVAFvcBYOk0I9DJtvclvFnDBYV8T69HMGzCmuIibHrw4ImB+VCwLFk7M7lsBgSo5FDS1z8swgMyTsKKFmsLOFmvMXwF+arLIQRNYLwTs/JyPl6ExjQJqfNhVu/A1SqAc2wm1Tg n2i0m+9oj0HI5HZ5VX23T4f2Aew2AxascByQx6ue47avziBtV9c84IpnpFTbrozPkXWKlyjXEY9YArw6LqKg1mn7iQAWoeVQOvC8Kv6O2CVCw+RCLzHiZs8lpu/vwtyJ8hhNoI+tJLKm/Va5C9ZnwIDAQAB".to_owned());

        let result = verify_email_with_resolver(logger, &email, &resolver).unwrap();
        assert!(result.summary() == "pass");

        let from_list =
            addrparse_header(email.get_headers().get_first_header("From").unwrap()).unwrap();

        let addr = match &from_list[0] {
            mailparse::MailAddr::Single(single_email) => single_email.addr.clone(),
            _ => panic!("invalid From header"),
        };

        (
            addr,
            email
                .get_headers()
                .get_first_header("Subject")
                .unwrap()
                .get_value(),
        )
    }

    fn validate_key(key: &String) {
        assert!(key.starts_with("ed25519:"));
        assert_eq!(key.len(), 52);
        assert!(key
            .strip_prefix("ed25519:")
            .unwrap()
            .chars()
            .all(|x| match x {
                'A'..='Z' => true,
                'a'..='z' => true,
                '0'..='9' => true,
                _ => panic!("invalid char {}", x),
            }));
    }

    fn parse_command(header: String) -> CommandEnum {
        if header == "init" {
            return CommandEnum::Init;
        }

        if header.starts_with("add_key") {
            let key = header.strip_prefix("add_key").unwrap().trim().to_owned();
            AuthManager::validate_key(&key);
            return CommandEnum::AddKey(key);
        }

        if header.starts_with("delete_key") {
            return CommandEnum::DeleteKey;
        }

        if header.starts_with("transfer") {
            return CommandEnum::Transfer;
        }
        panic!("Wrong header");
    }

    fn sender_to_account(sender: String) -> String {
        sender
            .chars()
            .map(|x| match x {
                'a'..='z' => x,
                'A'..='Z' => x,
                '0'..='9' => x,
                '@' => x,
                '.' => '_',
                '_' => x,
                '-' => x,
                _ => panic!("Unsupported char {}", x),
            })
            .collect()
    }

    pub fn receive_email(full_email: &[u8]) {
        // verify email
        let (sender, header) = AuthManager::verify_email(full_email);
        let prefix = AuthManager::sender_to_account(sender);
        let cmd = AuthManager::parse_command(header);
        match cmd {
            CommandEnum::Init => AuthManager::create_new_subaccount(prefix),
            CommandEnum::AddKey(key) => AuthManager::add_key(prefix, key),
            _ => todo!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    pub fn test_parse_command() {
        assert_eq!(
            AuthManager::parse_command("init".to_owned()),
            CommandEnum::Init
        );

        assert_eq!(
            AuthManager::parse_command(
                "add_key ed25519:3tXAA9zf5YSLxYELSbxwhEvMd7h9itTfCcUfEc3QfPgD".to_owned()
            ),
            CommandEnum::AddKey("ed25519:3tXAA9zf5YSLxYELSbxwhEvMd7h9itTfCcUfEc3QfPgD".to_owned())
        );
        assert_eq!(
            AuthManager::parse_command(
                "add_key     ed25519:3tXAA9zf5YSLxYELSbxwhEvMd7h9itTfCcUfEc3QfPgD 
                \n"
                .to_owned()
            ),
            CommandEnum::AddKey("ed25519:3tXAA9zf5YSLxYELSbxwhEvMd7h9itTfCcUfEc3QfPgD".to_owned())
        );
    }

    #[test]
    pub fn verify_email() {
        assert_eq!(
            AuthManager::verify_email(include_bytes!("message.eml")),
            (
                "example.near@gmail.com".to_owned(),
                "Another message".to_owned()
            )
        );
    }
    #[test]
    #[should_panic]
    pub fn verify_invalid_email() {
        assert_eq!(
            AuthManager::verify_email(include_bytes!("invalid_message.eml")),
            (
                "example.near@gmail.com".to_owned(),
                "Another message".to_owned()
            )
        );
    }
}
