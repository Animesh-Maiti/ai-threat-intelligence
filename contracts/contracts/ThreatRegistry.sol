// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ThreatRegistry {
    mapping(bytes32 => bool) public threats;

    function register(bytes32 threatId) external {
        threats[threatId] = true;
    }
}
