# Introduction
This is the smart contract for security questions. A user can save an answer to the questions and later verify his identity with it. 

# Setup
First install ganache-cli and truffle
* Next start ganache and deploy the smart contract:
  * ganache-cli -h 0.0.0.0
  * truffle migrate --network=ganache

This deploys the smart contract. You should note the address at which the smart contract was deployed.

If you have troubles with stack size please use the following command to fix it:
`node --stack-size=1200 ./node_modules/.bin/truffle migrate --reset --network ganache`

# Cost
The process of answer validation works as follows:
* First the user creates a group with an answer (one-time)
* If the user wants to attempt an answer:
  * Uploads the attempt ("query")
  * The parties upload their part ("AddPart")
  * The user gives gas to the smart contract to verify the attempt ("verdict") 
