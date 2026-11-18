// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Vault - deliberately vulnerable sample for AuditGraph.
/// @notice DO NOT USE IN PRODUCTION. This contract is intentionally
/// insecure so AuditGraph has real findings and attack paths to show:
/// reentrancy (withdraw -> call.value), unprotected initializer,
/// arbitrary delegatecall, unprotected selfdestruct, tx.origin auth.
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;
    bool public initialized;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    /// @notice Unprotected initializer - anyone can become owner.
    function initialize(address _owner) public {
        require(!initialized, "already initialized");
        owner = _owner;
        initialized = true;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice Vulnerable: external call BEFORE the state update.
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] -= amount;
        emit Withdraw(msg.sender, amount);
    }

    /// @notice Calls withdraw - gives the graph a CALLS edge into the sink.
    function drain() public {
        withdraw(balances[msg.sender]);
    }

    /// @notice Arbitrary delegatecall - caller controls target and data.
    function delegate(address target, bytes calldata data) public returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }

    /// @notice Unprotected selfdestruct.
    function kill() public {
        selfdestruct(payable(owner));
    }

    /// @notice tx.origin used for authorization.
    function emergencyWithdraw(uint256 amount) public {
        require(tx.origin == owner, "not owner");
        withdraw(amount);
    }
}
