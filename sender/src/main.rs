use std::{env, time::Duration};

use near_crypto::SecretKey;
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::{
    transaction::{Action, FunctionCallAction, Transaction},
    types::{AccountId, BlockReference},
};

use serde_json::json;

extern crate imap;
extern crate native_tls;

fn fetch_inbox_from(
    min_value: u32,
    username: &str,
    password: &str,
) -> imap::error::Result<(u32, Vec<String>)> {
    let domain = "imap.gmail.com";
    let tls = native_tls::TlsConnector::builder().build().unwrap();

    // we pass in the domain twice to check that the server's TLS
    // certificate is valid for the domain we're connecting to.
    let client = imap::connect((domain, 993), domain, &tls).unwrap();

    // the client we have here is unauthenticated.
    // to do anything useful with the e-mails, we need to log in
    let mut imap_session = client.login(username, password).map_err(|e| e.0)?;

    // we want to fetch the first email in the INBOX mailbox
    let mailbox = imap_session.select("INBOX")?;

    let result = if mailbox.exists > min_value {
        let max_value = mailbox.exists;
        let foo = (min_value + 1..=max_value).map(|x| format!("{}", x));

        let messages = imap_session.fetch(itertools::join(foo, ","), "RFC822")?;

        Ok((
            max_value,
            messages
                .iter()
                .map(|message| {
                    let body = message.body().expect("message did not have a body!");
                    std::str::from_utf8(body)
                        .expect("message was not valid utf-8")
                        .to_string()
                })
                .collect(),
        ))
    } else {
        Ok((min_value, vec![]))
    };
    imap_session.logout()?;

    result
}

async fn send_mail_to_near(
    mail: String,
    signer_account_id: &AccountId,
    signer_secret_key: &SecretKey,
    nonce: Option<u64>,
) -> Result<u64, Box<dyn std::error::Error>> {
    let client = JsonRpcClient::connect("http://localhost:3030");

    let signer = near_crypto::InMemorySigner::from_secret_key(
        signer_account_id.clone(),
        signer_secret_key.clone(),
    );

    let access_key_query_response = client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: signer.account_id.clone(),
                public_key: signer.public_key.clone(),
            },
        })
        .await?;
    let current_nonce = match access_key_query_response.kind {
        QueryResponseKind::AccessKey(access_key) => access_key.nonce,
        _ => Err("failed to extract current nonce")?,
    };

    let nonce = if let Some(nonce) = nonce {
        std::cmp::max(nonce, current_nonce)
    } else {
        current_nonce
    };

    println!("Will use nonce {}", nonce + 1);

    let payload = mail.as_bytes().to_vec();

    let transaction = Transaction {
        signer_id: signer.account_id.clone(),
        public_key: signer.public_key.clone(),
        nonce: nonce + 1,
        receiver_id: signer_account_id.clone(),
        block_hash: access_key_query_response.block_hash,
        actions: vec![Action::FunctionCall(FunctionCallAction {
            method_name: "receive_email".to_string(),
            args: json!({ "full_email": payload }).to_string().into_bytes(),
            gas: 300_000_000_000_000, // 100 TeraGas
            deposit: 0,
        })],
    };

    let request = methods::broadcast_tx_async::RpcBroadcastTxAsyncRequest {
        signed_transaction: transaction.sign(&signer),
    };

    let tx_hash = client.call(request).await?;

    println!("Sent request {}", tx_hash);

    Ok(nonce + 1)
}

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let near_account: AccountId = env::var("SENDER_NEAR_ACCOUNT")?.parse().unwrap();
    let near_account_secret_key: SecretKey = env::var("SENDER_SECRET_KEY")?.parse().unwrap();
    let imap_username = env::var("SENDER_IMAP_USERNAME")?;
    let imap_password = env::var("SENDER_IMAP_PASSWORD")?;

    println!("Starting...");

    // CHANGE.
    let mut min_value = 0;
    let (value, _) =
        fetch_inbox_from(min_value, imap_username.as_str(), imap_password.as_str()).unwrap();
    min_value = value;
    println!("Already {} email present - ignoring.", min_value);

    loop {
        let (value, mails) =
            fetch_inbox_from(min_value, imap_username.as_str(), imap_password.as_str()).unwrap();
        min_value = value;
        let mut nonce = None;
        if mails.len() > 0 {
            println!("Got new mail: {:?}", mails.len());
            for mail in mails.iter() {
                let result =
                    send_mail_to_near(mail.clone(), &near_account, &near_account_secret_key, nonce)
                        .await?;
                nonce = Some(result);
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
