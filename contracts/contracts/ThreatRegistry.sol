// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatRegistry
 * @dev Decentralized, tamper-evident audit ledger for AI threat intelligence reports.
 */
contract ThreatRegistry {
    address public immutable owner;

    struct ThreatRecord {
        bytes32 reportHash;
        string target;
        string riskLevel;
        uint256 confidenceScore; // Scaled by 100 (e.g. 85 = 0.85)
        uint256 timestamp;
        address loggedBy;
    }

    // Mapping from SHA-256 report hash to ThreatRecord
    mapping(bytes32 => ThreatRecord) public registry;
    bytes32[] public reportHashes;

    event ThreatLogged(
        bytes32 indexed reportHash,
        string target,
        string riskLevel,
        uint256 confidenceScore,
        uint256 timestamp,
        address indexed loggedBy
    );

    constructor() {
        owner = msg.sender;
    }

    function logThreat(
        bytes32 _reportHash,
        string calldata _target,
        string calldata _riskLevel,
        uint256 _confidenceScore
    ) external returns (bool) {
        require(registry[_reportHash].timestamp == 0, "Threat report already registered");

        ThreatRecord memory record = ThreatRecord({
            reportHash: _reportHash,
            target: _target,
            riskLevel: _riskLevel,
            confidenceScore: _confidenceScore,
            timestamp: block.timestamp,
            loggedBy: msg.sender
        });

        registry[_reportHash] = record;
        reportHashes.push(_reportHash);

        emit ThreatLogged(
            _reportHash,
            _target,
            _riskLevel,
            _confidenceScore,
            block.timestamp,
            msg.sender
        );

        return true;
    }

    function verifyReport(bytes32 _reportHash)
        external
        view
        returns (
            bool exists,
            string memory target,
            string memory riskLevel,
            uint256 confidenceScore,
            uint256 timestamp,
            address loggedBy
        )
    {
        ThreatRecord memory r = registry[_reportHash];
        if (r.timestamp == 0) {
            return (false, "", "", 0, 0, address(0));
        }
        return (true, r.target, r.riskLevel, r.confidenceScore, r.timestamp, r.loggedBy);
    }

    function totalReports() external view returns (uint256) {
        return reportHashes.length;
    }
}