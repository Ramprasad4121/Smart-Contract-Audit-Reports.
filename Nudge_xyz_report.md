## [M-1]Missing Reentrancy Protection in `deployAndFundCampaign` function, Allows Potential Reentrancy Attacks

Finding description and impact
The function `deployAndFundCampaign` in `NudgeCampaignFactory.sol` forwards ETH to the deployed campaign contract before marking it as deployed. This allows a potential reentrancy attack if the deployed campaign contract is attacker-controlled and executes a callback that re-enters the function before state changes are committed.

•Multiple Campaign Deployments: An attacker could trigger multiple campaign deployments with the same parameters before the contract recognizes the first deployment.
•Unexpected Fund Transfers: If the attacker reenters the function before the deployment is finalized, they may be able to manipulate the ETH transfer logic.
•State Inconsistency: The isCampaign[campaign] = true; assignment happens after fund transfers, leading to a temporary window where the campaign is not recognized, allowing an attacker to exploit this gap.

Proof of Concept
Vulnerable Code:
```
 //@audit: chance of reentrancy here
 // Then send ETH
(bool sent, ) = campaign.call{value: initialRewardAmount}("");
if (!sent) revert NativeTokenTransferFailed();
```
•This forwards ETH before updating the campaign tracking isCampaign[campaign] = true; inside deployCampaign.

Attack Scenario:
1.Attacker Deploys Malicious Contract that accepts ETH and triggers a callback.
2.Attacker Calls deployAndFundCampaign, causing ETH to be forwarded to their contract.
3.Malicious Contract Reenters deployAndFundCampaign, forcing multiple campaign deployments before isCampaign[campaign] = true; is set.
4.This would result:
•The attacker can bypass campaign tracking, deploying multiple campaigns.
•ETH can be rerouted or drained in unexpected ways.

=> Poc

contract MaliciousCampaign {
    NudgeCampaignFactory factory;
    bool reentered = false;

    constructor(address _factory) {
        factory = NudgeCampaignFactory(_factory);
    }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            // Reenter deployAndFundCampaign with the same parameters
            factory.deployAndFundCampaign(
                86400,
                address(this),
                address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE), // native token
                1000,
                msg.sender,
                block.timestamp,
                msg.sender,
                msg.value,
                12345
            );
        }
    }
    }

PoC Steps:
=> Deploy MaliciousCampaign with the address of NudgeCampaignFactory.
=> Call deployAndFundCampaign with ETH.
=> Observe multiple unintended campaign deployments due to reentrancy.

Recommended mitigation steps
=> Use OpenZeppelin’s ReentrancyGuard

•Modify NudgeCampaignFactory.sol to inherit ReentrancyGuard:
contract NudgeCampaignFactory is INudgeCampaignFactory, AccessControl, ReentrancyGuard {

•Apply the nonReentrant modifier to deployAndFundCampaign:

function deployAndFundCampaign(...) external payable nonReentrant returns (address campaign) {

=> Use Checks-Effects-Interactions Pattern
•Move isCampaign[campaign] = true; before the ETH transfer:

```
isCampaign[campaign] = true;
(bool sent, ) = campaign.call{value: initialRewardAmount}("");
if (!sent) revert NativeTokenTransferFailed();
```

=> Limit Gas for External Calls
•Use a gas-limited transfer instead of .call{value: amount}("");
```
(bool sent, ) = campaign.call{value: initialRewardAmount, gas: 2300}("");
if (!sent) revert NativeTokenTransferFailed();
```
