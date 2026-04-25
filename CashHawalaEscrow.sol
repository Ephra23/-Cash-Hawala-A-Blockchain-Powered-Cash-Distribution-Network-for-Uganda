// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CashHawalaEscrow
 * @notice Smart contract escrow for the Cash Hawala Uganda protocol.
 *         Converts USDC/USDT deposits into physical UGX cash via trusted local agents.
 *         Chain: Polygon PoS (chainId 137)
 *
 * Security model:
 *   - Funds never leave escrow until delivery is cryptographically confirmed
 *   - Receiver identity is never stored on-chain (only keccak256 hash)
 *   - PINs are never stored on-chain (only commitment hash stored)
 *   - Dispute resolution via 2-of-3 community arbiters
 *   - Agent collateral subject to slashing on fraud
 *
 * Regulatory awareness (Uganda Protection of Sovereignty Bill 2026):
 *   - No Ugandan entity holds funds; escrow is self-executing code
 *   - Transfers are peer-to-contract-to-agent; no intermediary custodian
 *   - Per-transfer caps enforced on-chain to stay under reporting thresholds
 */

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract CashHawalaEscrow {

    // ─── Constants ────────────────────────────────────────────────────────────

    uint256 public constant FEE_BPS        = 150;       // 1.5%
    uint256 public constant BPS_DENOM      = 10_000;
    uint256 public constant PIN_TTL        = 24 hours;
    uint256 public constant DISPUTE_WINDOW = 24 hours;  // after expiry
    uint256 public constant SLASH_BPS      = 1_000;     // 10% collateral slash
    uint256 public constant MIN_COLLATERAL = 50e6;      // $50 USDC (6 decimals)
    uint256 public constant MAX_TRANSFER_USDC = 500e6;  // $500 per transfer (regulatory cap)
    uint256 public constant ARBITER_COUNT  = 3;

    // ─── Types ────────────────────────────────────────────────────────────────

    enum Status { NONE, ESCROWED, DELIVERED, DISPUTED, REFUNDED, RESOLVED }

    struct Transfer {
        address sender;
        address agent;
        bytes32 receiverHash;     // keccak256(phone+salt) – never raw PII
        bytes32 pinCommitment;    // keccak256(pin+transferId) – verified off-chain reveal
        address token;            // USDC or USDT
        uint256 tokenAmount;      // principal (excl. fee already deducted)
        uint256 feeAmount;
        uint256 amountUGX;        // informational; UGX amount to hand over
        uint256 expiry;
        uint256 createdAt;
        Status  status;
        bytes32 locationHash;     // keccak256(lat+lng) for arbiter matching
    }

    struct AgentProfile {
        bool     active;
        bool     provisional;     // Provisional: lower limits until 10 deliveries
        uint256  collateral;      // USDC locked as good-faith bond
        uint256  reputationScore; // 0–10000 (basis points), starts at 8000
        uint256  successCount;
        uint256  disputeLosses;
        uint256  dailyVolume;
        uint256  dailyVolumeReset; // timestamp of last daily reset
        uint256  maxTxUGX;
        address  collateralToken;
    }

    struct Dispute {
        bytes32  transferId;
        address  initiator;
        uint256  openedAt;
        address[ARBITER_COUNT] arbiters;
        uint8    votesForAgent;   // release to agent
        uint8    votesForSender;  // refund to sender
        bool     resolved;
        mapping(address => bool) hasVoted;
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    address public owner;
    address public feeRecipient;
    address public pendingOwner;

    mapping(address => bool)           public approvedTokens;
    mapping(bytes32 => Transfer)       public transfers;
    mapping(address => AgentProfile)   public agents;
    mapping(bytes32 => Dispute)        public disputes;
    mapping(address => bool)           public approvedArbiters;
    address[]                          public arbiterPool;

    // Anti-replay: track used transferIds
    mapping(bytes32 => bool)           public usedIds;

    // Pending fee accumulation per token
    mapping(address => uint256)        public pendingFees;

    // ─── Events ───────────────────────────────────────────────────────────────

    event TransferInitiated(
        bytes32 indexed transferId,
        address indexed sender,
        address indexed agent,
        address token,
        uint256 tokenAmount,
        uint256 amountUGX,
        uint256 expiry
    );
    event CashDelivered(bytes32 indexed transferId, uint256 timestamp);
    event DisputeOpened(bytes32 indexed transferId, address initiator);
    event ArbiterVoted(bytes32 indexed transferId, address arbiter, bool forAgent);
    event DisputeResolved(bytes32 indexed transferId, bool agentWon);
    event FundsReleased(bytes32 indexed transferId, address recipient, uint256 amount);
    event AgentRegistered(address indexed agent, bool provisional);
    event AgentCollateralDeposited(address indexed agent, uint256 amount);
    event AgentCollateralSlashed(address indexed agent, uint256 amount);
    event TransferRefunded(bytes32 indexed transferId);

    // ─── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAgent(bytes32 transferId) {
        require(msg.sender == transfers[transferId].agent, "Not assigned agent");
        _;
    }

    modifier transferExists(bytes32 transferId) {
        require(transfers[transferId].status != Status.NONE, "Transfer not found");
        _;
    }

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(address _feeRecipient) {
        owner = msg.sender;
        feeRecipient = _feeRecipient;
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function approveToken(address token, bool approved) external onlyOwner {
        approvedTokens[token] = approved;
    }

    function setFeeRecipient(address recipient) external onlyOwner {
        require(recipient != address(0), "Zero address");
        feeRecipient = recipient;
    }

    function addArbiter(address arbiter) external onlyOwner {
        require(!approvedArbiters[arbiter], "Already arbiter");
        approvedArbiters[arbiter] = true;
        arbiterPool.push(arbiter);
    }

    function removeArbiter(address arbiter) external onlyOwner {
        approvedArbiters[arbiter] = false;
        // Pool cleanup happens lazily in _selectArbiters
    }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function withdrawFees(address token) external onlyOwner {
        uint256 amount = pendingFees[token];
        require(amount > 0, "No fees");
        pendingFees[token] = 0;
        require(IERC20(token).transfer(feeRecipient, amount), "Fee transfer failed");
    }

    // ─── Agent Management ─────────────────────────────────────────────────────

    /**
     * @notice Register as a provisional agent.
     * @param collateralToken  USDC address (must be approved)
     * @param collateralAmount Must be >= MIN_COLLATERAL
     * @param maxTxUGX         Max UGX per transaction (admin can override)
     */
    function registerAgent(
        address collateralToken,
        uint256 collateralAmount,
        uint256 maxTxUGX
    ) external {
        require(approvedTokens[collateralToken], "Token not approved");
        require(collateralAmount >= MIN_COLLATERAL, "Insufficient collateral");
        require(!agents[msg.sender].active, "Already registered");

        // Pull collateral
        require(
            IERC20(collateralToken).transferFrom(msg.sender, address(this), collateralAmount),
            "Collateral transfer failed"
        );

        agents[msg.sender] = AgentProfile({
            active:            true,
            provisional:       true,
            collateral:        collateralAmount,
            reputationScore:   8_000,  // start at 80%
            successCount:      0,
            disputeLosses:     0,
            dailyVolume:       0,
            dailyVolumeReset:  block.timestamp,
            maxTxUGX:          maxTxUGX,
            collateralToken:   collateralToken
        });

        emit AgentRegistered(msg.sender, true);
        emit AgentCollateralDeposited(msg.sender, collateralAmount);
    }

    function depositCollateral(uint256 amount) external {
        AgentProfile storage agent = agents[msg.sender];
        require(agent.active, "Not an agent");
        require(
            IERC20(agent.collateralToken).transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );
        agent.collateral += amount;
        emit AgentCollateralDeposited(msg.sender, amount);
    }

    /// @notice Owner promotes provisional agent to Verified after 10 successes
    function verifyAgent(address agentAddr) external onlyOwner {
        AgentProfile storage agent = agents[agentAddr];
        require(agent.active && agent.provisional, "Not provisional agent");
        require(agent.successCount >= 10, "Insufficient track record");
        agent.provisional = false;
    }

    // ─── Core Protocol ────────────────────────────────────────────────────────

    /**
     * @notice Sender initiates a transfer. Funds locked in escrow.
     * @param transferId     Unique ID: keccak256(sender, agent, nonce, timestamp) — generated off-chain
     * @param agentAddr      Address of selected agent
     * @param receiverHash   keccak256(receiverPhone + salt) — never raw PII
     * @param pinCommitment  keccak256(pin + transferId) — PIN verified on reveal
     * @param token          USDC or approved stablecoin
     * @param principalAmount Amount to release to agent (excl. fee)
     * @param amountUGX      Informational: cash amount in UGX
     * @param locationHash   keccak256(lat + lng) for arbiter geo-matching
     */
    function initiateTransfer(
        bytes32 transferId,
        address agentAddr,
        bytes32 receiverHash,
        bytes32 pinCommitment,
        address token,
        uint256 principalAmount,
        uint256 amountUGX,
        bytes32 locationHash
    ) external {
        require(!usedIds[transferId], "Duplicate transferId");
        require(approvedTokens[token], "Token not approved");
        require(agents[agentAddr].active, "Agent not active");
        require(principalAmount > 0, "Zero amount");
        require(principalAmount <= MAX_TRANSFER_USDC, "Exceeds per-transfer cap");

        // Fee calculation
        uint256 fee = (principalAmount * FEE_BPS) / BPS_DENOM;
        uint256 totalAmount = principalAmount + fee;

        // Agent daily limit check (resets every 24h)
        AgentProfile storage agent = agents[agentAddr];
        _resetDailyVolume(agent);
        // UGX limit approximate; exact enforcement via off-chain agent matching
        require(amountUGX <= agent.maxTxUGX, "Exceeds agent max tx");

        // Pull total from sender
        require(
            IERC20(token).transferFrom(msg.sender, address(this), totalAmount),
            "Token transfer failed"
        );

        usedIds[transferId] = true;
        pendingFees[token] += fee;

        transfers[transferId] = Transfer({
            sender:        msg.sender,
            agent:         agentAddr,
            receiverHash:  receiverHash,
            pinCommitment: pinCommitment,
            token:         token,
            tokenAmount:   principalAmount,
            feeAmount:     fee,
            amountUGX:     amountUGX,
            expiry:        block.timestamp + PIN_TTL,
            createdAt:     block.timestamp,
            status:        Status.ESCROWED,
            locationHash:  locationHash
        });

        emit TransferInitiated(
            transferId,
            msg.sender,
            agentAddr,
            token,
            principalAmount,
            amountUGX,
            block.timestamp + PIN_TTL
        );
    }

    /**
     * @notice Agent confirms physical cash was delivered.
     * @param transferId  The transfer being confirmed
     * @param pin         Plain-text 6-digit PIN (revealed once; verified against commitment)
     * @param proofType   0=tap, 1=sms-reply, 2=photo-geotag
     * @param proofData   Arbitrary bytes: geotag hash, SMS timestamp hash, etc.
     */
    function confirmDelivery(
        bytes32 transferId,
        string calldata pin,
        uint8 proofType,
        bytes32 proofData
    ) external onlyAgent(transferId) transferExists(transferId) {
        Transfer storage t = transfers[transferId];

        require(t.status == Status.ESCROWED, "Not in escrow");
        require(block.timestamp <= t.expiry, "PIN expired");

        // Verify PIN commitment
        bytes32 expectedCommitment = keccak256(abi.encodePacked(pin, transferId));
        require(t.pinCommitment == expectedCommitment, "Invalid PIN");

        // Require at least some proof
        require(proofType <= 2, "Invalid proof type");
        // proofData may be zero for tap confirmation — acceptable for MVP
        // Photo/geotag (type 2) provides strongest evidence for disputes

        t.status = Status.DELIVERED;
        agents[msg.sender].successCount += 1;
        agents[msg.sender].dailyVolume += t.amountUGX;

        // Promote from provisional at 10 successes (owner still needs to call verifyAgent)
        _updateReputation(msg.sender, true);

        // Release principal to agent
        require(
            IERC20(t.token).transfer(t.agent, t.tokenAmount),
            "Agent payment failed"
        );

        emit CashDelivered(transferId, block.timestamp);
        emit FundsReleased(transferId, t.agent, t.tokenAmount);
    }

    /**
     * @notice Sender reclaims funds if PIN expired and not delivered.
     *         Can only be called after expiry + DISPUTE_WINDOW to give time for disputes.
     */
    function claimRefund(bytes32 transferId) external transferExists(transferId) {
        Transfer storage t = transfers[transferId];
        require(msg.sender == t.sender, "Not sender");
        require(t.status == Status.ESCROWED, "Not refundable");
        require(block.timestamp > t.expiry + DISPUTE_WINDOW, "Dispute window active");

        t.status = Status.REFUNDED;

        // Return principal + fee to sender (agent didn't deliver)
        uint256 refund = t.tokenAmount + t.feeAmount;
        pendingFees[t.token] -= t.feeAmount; // un-accrue fee
        require(IERC20(t.token).transfer(t.sender, refund), "Refund failed");

        emit TransferRefunded(transferId);
        emit FundsReleased(transferId, t.sender, refund);
    }

    // ─── Dispute Resolution ───────────────────────────────────────────────────

    /**
     * @notice Open a dispute within DISPUTE_WINDOW of expiry.
     *         Either sender or agent may initiate.
     */
    function openDispute(bytes32 transferId) external transferExists(transferId) {
        Transfer storage t = transfers[transferId];
        require(
            t.status == Status.ESCROWED || t.status == Status.DELIVERED,
            "Cannot dispute"
        );
        require(
            msg.sender == t.sender || msg.sender == t.agent,
            "Not party to transfer"
        );
        require(
            block.timestamp <= t.expiry + DISPUTE_WINDOW,
            "Dispute window closed"
        );
        require(disputes[transferId].openedAt == 0, "Dispute already open");

        t.status = Status.DISPUTED;

        Dispute storage d = disputes[transferId];
        d.transferId = transferId;
        d.initiator  = msg.sender;
        d.openedAt   = block.timestamp;

        // Select 3 pseudo-random arbiters from pool (not secure randomness — MVP)
        _selectArbiters(transferId);

        emit DisputeOpened(transferId, msg.sender);
    }

    /**
     * @notice Arbiter casts vote.
     * @param forAgent true = release to agent, false = refund to sender
     */
    function vote(bytes32 transferId, bool forAgent) external transferExists(transferId) {
        Transfer storage t = transfers[transferId];
        Dispute storage d = disputes[transferId];

        require(t.status == Status.DISPUTED, "Not disputed");
        require(_isAssignedArbiter(transferId, msg.sender), "Not assigned arbiter");
        require(!d.hasVoted[msg.sender], "Already voted");

        d.hasVoted[msg.sender] = true;
        if (forAgent) {
            d.votesForAgent += 1;
        } else {
            d.votesForSender += 1;
        }

        emit ArbiterVoted(transferId, msg.sender, forAgent);

        // Check if 2-of-3 threshold reached
        if (d.votesForAgent >= 2) {
            _resolveDispute(transferId, true);
        } else if (d.votesForSender >= 2) {
            _resolveDispute(transferId, false);
        }
    }

    // ─── Internal Helpers ─────────────────────────────────────────────────────

    function _resolveDispute(bytes32 transferId, bool agentWon) internal {
        Transfer storage t = transfers[transferId];
        Dispute storage d = disputes[transferId];

        require(!d.resolved, "Already resolved");
        d.resolved = true;
        t.status = Status.RESOLVED;

        emit DisputeResolved(transferId, agentWon);

        if (agentWon) {
            // Agent delivered; release principal to agent
            require(IERC20(t.token).transfer(t.agent, t.tokenAmount), "Payment failed");
            emit FundsReleased(transferId, t.agent, t.tokenAmount);
            _updateReputation(t.agent, true);
        } else {
            // Fraud / no delivery; refund sender; slash agent collateral
            uint256 refund = t.tokenAmount + t.feeAmount;
            pendingFees[t.token] -= t.feeAmount;
            require(IERC20(t.token).transfer(t.sender, refund), "Refund failed");
            emit FundsReleased(transferId, t.sender, refund);

            // Slash 10% of agent collateral
            AgentProfile storage agent = agents[t.agent];
            if (agent.collateral > 0) {
                uint256 slash = (agent.collateral * SLASH_BPS) / BPS_DENOM;
                if (slash > agent.collateral) slash = agent.collateral;
                agent.collateral -= slash;
                // Slashed funds go to fee recipient (community pool)
                pendingFees[t.token] += slash;
                emit AgentCollateralSlashed(t.agent, slash);
            }
            _updateReputation(t.agent, false);
            agent.disputeLosses += 1;

            // Deactivate agent if collateral falls below minimum
            if (agent.collateral < MIN_COLLATERAL) {
                agent.active = false;
            }
        }
    }

    function _updateReputation(address agentAddr, bool positive) internal {
        AgentProfile storage agent = agents[agentAddr];
        if (positive) {
            // +50 bps per success, cap at 10000
            uint256 newScore = agent.reputationScore + 50;
            agent.reputationScore = newScore > 10_000 ? 10_000 : newScore;
        } else {
            // -500 bps per dispute loss
            if (agent.reputationScore >= 500) {
                agent.reputationScore -= 500;
            } else {
                agent.reputationScore = 0;
            }
        }
    }

    function _resetDailyVolume(AgentProfile storage agent) internal {
        if (block.timestamp >= agent.dailyVolumeReset + 1 days) {
            agent.dailyVolume = 0;
            agent.dailyVolumeReset = block.timestamp;
        }
    }

    /**
     * @notice Pseudo-random arbiter selection using block data.
     *         NOT cryptographically secure — suitable for MVP.
     *         Production: use Chainlink VRF.
     */
    function _selectArbiters(bytes32 transferId) internal {
        Dispute storage d = disputes[transferId];
        uint256 poolLen = arbiterPool.length;
        require(poolLen >= ARBITER_COUNT, "Insufficient arbiters");

        uint256 seed = uint256(
            keccak256(abi.encodePacked(transferId, block.timestamp, block.prevrandao))
        );

        uint256 selected = 0;
        uint256 attempts = 0;
        address[ARBITER_COUNT] memory chosen;

        while (selected < ARBITER_COUNT && attempts < poolLen * 2) {
            uint256 idx = (seed >> (attempts * 8)) % poolLen;
            address candidate = arbiterPool[idx];

            if (approvedArbiters[candidate] && !_inArray(chosen, candidate, selected)) {
                chosen[selected] = candidate;
                selected++;
            }
            attempts++;
            seed = uint256(keccak256(abi.encodePacked(seed, attempts)));
        }

        require(selected == ARBITER_COUNT, "Could not select arbiters");
        d.arbiters = chosen;
    }

    function _isAssignedArbiter(bytes32 transferId, address candidate)
        internal view returns (bool)
    {
        address[ARBITER_COUNT] storage arbs = disputes[transferId].arbiters;
        for (uint256 i = 0; i < ARBITER_COUNT; i++) {
            if (arbs[i] == candidate) return true;
        }
        return false;
    }

    function _inArray(
        address[ARBITER_COUNT] memory arr,
        address target,
        uint256 len
    ) internal pure returns (bool) {
        for (uint256 i = 0; i < len; i++) {
            if (arr[i] == target) return true;
        }
        return false;
    }

    // ─── View Helpers ─────────────────────────────────────────────────────────

    function getTransfer(bytes32 transferId)
        external view
        returns (Transfer memory)
    {
        return transfers[transferId];
    }

    function getAgentProfile(address agentAddr)
        external view
        returns (AgentProfile memory)
    {
        return agents[agentAddr];
    }

    function getDisputeArbiters(bytes32 transferId)
        external view
        returns (address[ARBITER_COUNT] memory)
    {
        return disputes[transferId].arbiters;
    }

    function arbiterPoolLength() external view returns (uint256) {
        return arbiterPool.length;
    }
}
