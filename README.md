# Proof-of-Concept for email-based authentication for NEAR

The goal of this repo is to show the Proof of concept of using the DKIM signatures (added by default to emails) as a way to authenticate transactions.

This would allow users to control their NEAR account via email - by setting the command that they would like to execute in the subject, and then sending the email to one of the recipients.

Email would be signed by the sender's server (in current design, we only support gmail) - and this signature can be verified by the contract.
