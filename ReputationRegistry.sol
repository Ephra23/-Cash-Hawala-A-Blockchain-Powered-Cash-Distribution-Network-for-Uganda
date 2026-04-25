// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ReputationRegistry
 * @notice Off-chain-first reputation ledger for Cash Hawala agents.
 *         On-chain state is updated via signed oracle messages to avoid
 *         excessive gas usage on Polygon PoS.
 *
 *         The CashHawalaEscrow contract handles real-time rep updates for
 *         dispute outcomes. This registry adds a richer, aggregated view
 *         including diaspora vouches, location attestations, and
 *         cross-transfer analytics.
 */
contract ReputationRegistry {

    // ─── Types ────────────────────────────────────────────────────────────────

    struct AgentSummary {
        uint32  totalDeliveries;
        uint32  totalDisputes;
        uint32  disputeWins;      // agent won (kept payment)
        uint32  vouchCount;
        uint16  reputationBps;    // 0–10000
        bool    verified;
        uint256 lastActive;
        bytes32 locationRegion;   // keccak256(region string) for privacy
    }

    struct Vouch {
        address voucher;
        uint256 timestamp;
        bytes32 noteHash;         // keccak256 of optional attestation note
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    address public escrowContract;
    address public oracle;         // Cloudflare Worker signing key (EOA)
    address public owner;

    mapping(address => AgentSummary) public agentSummaries;
    mapping(address => Vouch[])      public vouches;
    mapping(address => mapping(address => bool)) public hasVouched;

    uint256 public constant MAX_VOUCHES_PER_AGENT = 10;
    uint256 public nonce;

    // ─── Events ───────────────────────────────────────────────────────────────

    event ReputationUpdated(address indexed agent, uint16 newScore);
    event AgentVouched(address indexed agent, address indexed voucher);
    event AgentVerified(address indexed agent);
    event OracleUpdated(address newOracle);

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(address _escrow, address _oracle) {
        escrowContract = _escrow;
        oracle = _oracle;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyEscrowOrOracle() {
        require(
            msg.sender == escrowContract || msg.sender == oracle,
            "Unauthorized updater"
        );
        _;
    }

    // ─── Oracle Updates ───────────────────────────────────────────────────────

    /**
     * @notice Oracle (Cloudflare Worker) pushes a signed batch reputation update.
     *         Signature: ECDSA over keccak256(agent, newScore, deliveries, disputes, nonce)
     */
    function updateReputation(
        address agent,
        uint16  newScore,
        uint32  deliveries,
        uint32  disputes,
        uint32  disputeWins,
        uint256 oracleNonce,
        bytes calldata signature
    ) external {
        // Verify oracle signature
        bytes32 msgHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encodePacked(
                agent, newScore, deliveries, disputes, disputeWins, oracleNonce
            ))
        ));
        address signer = _recoverSigner(msgHash, signature);
        require(signer == oracle, "Invalid oracle signature");
        require(oracleNonce > nonce, "Stale nonce");
        nonce = oracleNonce;

        AgentSummary storage s = agentSummaries[agent];
        s.reputationBps    = newScore;
        s.totalDeliveries  = deliveries;
        s.totalDisputes    = disputes;
        s.disputeWins      = disputeWins;
        s.lastActive       = block.timestamp;

        // Auto-verify if sufficient track record
        if (!s.verified && deliveries >= 10 && newScore >= 7_500) {
            s.verified = true;
            emit AgentVerified(agent);
        }

        emit ReputationUpdated(agent, newScore);
    }

    // ─── Vouching System ──────────────────────────────────────────────────────

    /**
     * @notice Community member vouches for an agent.
     *         Diaspora members, church groups, and community leaders vouch
     *         to bootstrap trust for new agents.
     */
    function vouchForAgent(
        address agent,
        bytes32 noteHash
    ) external {
        require(agentSummaries[agent].lastActive > 0 || _agentExists(agent), "Agent unknown");
        require(!hasVouched[msg.sender][agent], "Already vouched");
        require(
            vouches[agent].length < MAX_VOUCHES_PER_AGENT,
            "Max vouches reached"
        );
        require(msg.sender != agent, "Cannot self-vouch");

        hasVouched[msg.sender][agent] = true;
        vouches[agent].push(Vouch({
            voucher:   msg.sender,
            timestamp: block.timestamp,
            noteHash:  noteHash
        }));
        agentSummaries[agent].vouchCount += 1;

        emit AgentVouched(agent, msg.sender);
    }

    function getVouches(address agent) external view returns (Vouch[] memory) {
        return vouches[agent];
    }

    function getAgentSummary(address agent)
        external view
        returns (AgentSummary memory)
    {
        return agentSummaries[agent];
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function setOracle(address newOracle) external onlyOwner {
        oracle = newOracle;
        emit OracleUpdated(newOracle);
    }

    function setEscrowContract(address newEscrow) external onlyOwner {
        escrowContract = newEscrow;
    }

    // ─── Internals ────────────────────────────────────────────────────────────

    function _agentExists(address agent) internal view returns (bool) {
        // Check if registered in escrow — would require escrow interface call
        // For MVP, treat any address with vouches as existing
        return vouches[agent].length > 0;
    }

    function _recoverSigner(bytes32 hash, bytes calldata sig)
        internal pure returns (address)
    {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "Invalid signature v");
        return ecrecover(hash, v, r, s);
    }
}
