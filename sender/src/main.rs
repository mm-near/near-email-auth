use std::time;

use near_crypto::SecretKey;
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::{
    transaction::{Action, FunctionCallAction, Transaction},
    types::{AccountId, BlockReference},
};

use serde_json::json;

#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello, world!");
    let client = JsonRpcClient::connect("http://localhost:3030");
    let signer_account_id: AccountId = "shard0".parse().unwrap();
    let signer_secret_key: SecretKey = "ed25519:3JpzdrM9LPDv5dzCZngag91nzDqzPwGm44G6ocAwaXiCSFVb6W1vbd1Xq32PzikK65XXAppLNXqVfKAhnqCkpq2o".parse().unwrap();

    let signer = near_crypto::InMemorySigner::from_secret_key(signer_account_id, signer_secret_key);

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
    println!("Nonce is {}", current_nonce);

    let payload = include_bytes!("add_key.eml");
    let payload = payload.to_vec();

    let transaction = Transaction {
        signer_id: signer.account_id.clone(),
        public_key: signer.public_key.clone(),
        nonce: current_nonce + 1,
        receiver_id: "shard0".parse()?,
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

    //let sent_at = time::Instant::now();
    let tx_hash = client.call(request).await?;

    println!("Sent request {}", tx_hash);

    Ok(())
}
