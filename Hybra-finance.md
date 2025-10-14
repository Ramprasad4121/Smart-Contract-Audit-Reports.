# [H-01] Permanent Lock Balance Not Updated on Burn

## Summary
The `_burn` function in `VotingEscrow.sol` fails to decrement `permanentLockBalance` when burning a permanently locked NFT. This leaves the global permanent lock balance inflated forever, leading to overcounted voting power in governance checkpoints and totalSupply calculations

## Vulnerability Detail
In `lockPermanent(uint _tokenId)`, the contract adds the NFT's amount to permanentLockBalance and sets `locked[_tokenId].isPermanent = true`. However, `_burn(uint _tokenId)` only clears approvals, removes the token from the owner, updates delegation checkpoints, and emits Transfer—no adjustment to `permanentLockBalance`.
When a permanent NFT is burned (e.g., via withdraw after unlockPermanent, but directly via `_burn` in edge cases or internal calls), the balance stays stuck at the inflated value. This affects VotingBalanceLogic where `last_point.permanent = permanentLockBalance` in `_checkpoint`, propagating to `totalSupplyAtT` and user voting power.


## Impact
Inflates total voting supply and individual `balanceOfNFT` for permanent locks, enabling attackers to manipulate governance votes or exploit decayed power calculations. Permanent once set, so error is irreversible without manual intervention.

## Proof of Concept
Deployed a minimal test setup with Foundry. Here's the passing test confirming the issue:
``` solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.13;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol"; 
import {VotingEscrow} from "../contracts/VotingEscrow.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockERC20 is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public constant decimals = 18;
    string public constant name = "Mock";
    string public constant symbol = "MCK";

    function totalSupply() external pure returns (uint256) { return type(uint256).max; }

    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract TestVotingEscrow is VotingEscrow {
    constructor(address token_addr, address art_proxy) VotingEscrow(token_addr, art_proxy) {}
    function exposeBurn(uint _tokenId) external { _burn(_tokenId); }
}

contract VotingEscrowTest is Test {
    TestVotingEscrow ve;
    MockERC20 token;

    function setUp() public {
        token = new MockERC20();
        token.mint(address(this), 1000 ether);
        ve = new TestVotingEscrow(address(token), address(0x2));
        token.approve(address(ve), type(uint256).max);
    }

    function testPermanentBurnInflation() public {
        // Create & fund lock
        uint256 tokenId = ve.create_lock(100 ether, 52 weeks);
        ve.lockPermanent(tokenId); // Permanent: 100 ether

        assertEq(ve.permanentLockBalance(), 100 ether);

        // Direct _burn on permanent NFT (via exposeBurn)
        ve.exposeBurn(tokenId); // _burn called, no permanentLockBalance -=

        assertEq(ve.permanentLockBalance(), 100 ether); // Inflated: should be 0

        uint256 ts = block.timestamp;
        uint256 actualSupply = ve.totalSupplyAtT(ts);
        assertGt(actualSupply, 0); // Voting power overcount due to undeleted permanent
    }
}

```
Run `forge test --match-test testPermanentBurnInflation -vvvv`. Output shows permanentLockBalance() stuck at 100e18 post-burn, with totalSupplyAtT(1) returning ~49.86e18 (inflated voting power)

## Recommended Fix
In _burn, add
``` solidity
IVotingEscrow.LockedBalance memory lb = locked[_tokenId];
if (lb.isPermanent) {
    permanentLockBalance -= uint256(int256(lb.amount));
}
locked[_tokenId] = IVotingEscrow.LockedBalance(0, 0, false); // Clean up
```
Before removing the token. Also checkpoint the change to update slopes.

# [L-01] SetBribeFor event emits incorrect old value in _setExternalBribe function
## Impact
The `_setExternalBribe` function incorrectly emits `internal_bribes[_gauge]` as the old value in the SetBribeFor event, when it should emit `external_bribes[_gauge]`. This causes the event to log completely unrelated data, breaking the audit trail for external bribe changes.

Off-chain systems, subgraphs, and frontends that rely on this event to track bribe contract changes will receive misleading information about what the previous external bribe address was.

## Proof of Concept
```solidity
function _setExternalBribe(address _gauge, address _external) private {
    require(_external.code.length > 0, "CODELEN");
    emit SetBribeFor(false, internal_bribes[_gauge], _external, _gauge);  // @audit wrong old value
    external_bribes[_gauge] = _external;
}
```
The event signature is:
```solidity
event SetBribeFor(bool isInternal, address indexed old, address indexed latest, address indexed gauge);
```
For comparison, the internal bribe function correctly emits the old value:
```solidity
function _setInternalBribe(address _gauge, address _internal) private {
    require(_internal.code.length > 0, "CODELEN");
    emit SetBribeFor(true, internal_bribes[_gauge], _internal, _gauge);  // ✓ correct
    internal_bribes[_gauge] = _internal;
}
```
The issue is clear, when updating external bribes, the event shows the old internal bribe address instead of the old external bribe address. This makes it impossible to track what the previous external bribe contract was.

## Recommended Mitigation
```solidity
function _setExternalBribe(address _gauge, address _external) private {
    require(_external.code.length > 0, "CODELEN");
-   emit SetBribeFor(false, internal_bribes[_gauge], _external, _gauge);
+   emit SetBribeFor(false, external_bribes[_gauge], _external, _gauge);
    external_bribes[_gauge] = _external;
}
```
This ensures the event properly logs the transition from the old external bribe to the new one, maintaining consistency with how _setInternalBribe works and preserving an accurate historical record
