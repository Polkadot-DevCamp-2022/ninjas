# Ninjas
A distributed computing project powered by substrate blockchain framework, presented by Team 2.

## Initiative of the Project Name 

"A hiding ninja computes everything".
For a real good project, the users are not supposed to know all the details that happen at code-level. 
Just publish your mission on the blockchain-based platform, A loyal and trustworthy ninja will devote to 
this work.

## Workflow of the Project 

![substrateProject drawio](https://user-images.githubusercontent.com/8565556/169024493-b6895b3f-3810-4069-8361-fa6d59f9e208.svg)

- A user send a computation request transaction with an input.
- The input is not written on-chain but stored in the off-chain index while block creation.
- After a block creation, randomly select an ocw for each pending compute task.
- The ocw computes and sends signed transaction to notify the completion of computation, and store the result in the off-chain index.
- A user retrieve the computational result by sending a RPC to fetch off-chain index.
