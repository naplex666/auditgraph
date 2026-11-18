// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VaultSafe - guarded version of Vault for AuditGraph.
/// @notice Same shape as Vault (deposit / withdraw / drain), but safe:
/// checks-effects-interactions (state updated BEFORE the external call),
/// owner set once in the constructor, no delegatecall, no selfdestruct,
/// no tx.origin check, no initializer. This is the negative control:
/// Slither finds no High finding here and AuditGraph finds no sink path.
contract VaultSafe {
    mapping(address => uint256) public balances;
    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice Safe: effects (balances update) happen BEFORE the call.
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        emit Withdraw(msg.sender, amount);
    }

    function drain() public {
        withdraw(balances[msg.sender]);
    }
}
