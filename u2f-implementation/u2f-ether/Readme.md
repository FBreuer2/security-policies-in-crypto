# Introduction
This is an implementation of the server-side part of the U2F protocol on the Ethereum blockchain. 

No hardware key is needed to test the implementation since a software token (found in u2f-virtualtoken) is used for testing purposes.

The SmartContract implements U2F with curve SECP256R (standard) and with curve SECP256K (non-standard). This decision was made because the verification of signatures generated on curve SECP256K in Ethereum is a lot cheaper than verification of signatures on curve SECP256R. A user has the option to select which curve should be used for verification, since the user has to carry the cost of it.


Current benchmark:

Action | SECP256K (non-standard) | SECP256R (standard) | Factor (SECP256R/SECP256K)
------------ | ------------- | ------------- | -------------
Registration | 316919 | 1706232 | 5,38
Create transaction | 99115 | 99115 | 1
Verify transaction | 176090 | 1522286 | 8,6

# Setup
Get the required dependencies with

```
cd u2f-ether && npm install && cd ..
cd u2f-virtualtoken && npm install && cd ..
```

# Running tests/benchmarks
All tests can be run with
```
npm test
```
the output will also include benchmarks
