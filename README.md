# Proof-of-Concept for email-based authentication for NEAR

The goal of this repo is to show the Proof of concept of using the DKIM signatures (added by default to emails) as a way to authenticate transactions.

This would allow users to control their NEAR account via email - by setting the command that they would like to execute in the subject, and then sending the email to one of the recipients.

Email would be signed by the sender's server (in current design, we only support gmail) - and this signature can be verified by the contract.

## High level design

The setup consists of 3 sub-projects: worker contract, auth contract and server.

### workers
This is the contract that is running on the 'users' account - to handle delegated requests coming from the auth account.
If NEP 342 is approved, this will no longer be needed.

### auth
This is the main contract that takes are of validating DKIM messages - and passing them to workers (and creating workers accounts).

### server
This is the job that gets emails from the imap server - and sends them as transactions.

IMPORTANT: server doesn't actually have any special powers. It is acting more like a relayer - that takes the incoming email and executes the Near function call. If it tried to change anything in the email contents, then the signature verification in contract would have failed.
