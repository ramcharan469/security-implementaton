// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SecurityImplementation
 * @author Your Name
 * @notice A comprehensive smart contract demonstrating security best practices
 * @dev Implements multiple security patterns including access control, reentrancy protection, and secure fund management
 */
contract SecurityImplementation {
    // State variables
    address public owner;
    uint256 public totalFunds;
    bool private locked; // For reentrancy protection
    
    // Mappings
    mapping(address => uint256) public userBalances;
    mapping(address => bool) public authorizedUsers;
    
    // Events
    event FundsDeposited(address indexed user, uint256 amount, uint256 timestamp);
    event FundsWithdrawn(address indexed user, uint256 amount, uint256 timestamp);
    event UserAuthorized(address indexed user, address indexed authorizer, uint256 timestamp);
    event UserRevoked(address indexed user, address indexed revoker, uint256 timestamp);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    // Custom errors (gas efficient)
    error Unauthorized();
    error InsufficientBalance();
    error InvalidAmount();
    error TransferFailed();
    error ReentrancyDetected();
    error ZeroAddress();
    
    // Modifiers
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }
    
    modifier onlyAuthorized() {
        if (!authorizedUsers[msg.sender] && msg.sender != owner) revert Unauthorized();
        _;
    }
    
    modifier nonReentrant() {
        if (locked) revert ReentrancyDetected();
        locked = true;
        _;
        locked = false;
    }
    
    modifier validAmount(uint256 amount) {
        if (amount == 0) revert InvalidAmount();
        _;
    }
    
    modifier notZeroAddress(address addr) {
        if (addr == address(0)) revert ZeroAddress();
        _;
    }
    
    /**
     * @notice Constructor sets the contract deployer as the owner
     */
    constructor() {
        owner = msg.sender;
        authorizedUsers[msg.sender] = true;
        emit UserAuthorized(msg.sender, msg.sender, block.timestamp);
    }
    
    /**
     * @notice Securely deposit funds with proper validation and event emission
     * @dev Implements checks-effects-interactions pattern
     */
    function secureDeposit() external payable validAmount(msg.value) nonReentrant {
        // Checks
        require(msg.value > 0, "Deposit amount must be greater than zero");
        
        // Effects
        userBalances[msg.sender] += msg.value;
        totalFunds += msg.value;
        
        // Interactions (emit event)
        emit FundsDeposited(msg.sender, msg.value, block.timestamp);
    }
    
    /**
     * @notice Securely withdraw funds with reentrancy protection
     * @param amount The amount to withdraw
     * @dev Implements checks-effects-interactions pattern and reentrancy protection
     */
    function secureWithdraw(uint256 amount) external validAmount(amount) nonReentrant {
        // Checks
        if (userBalances[msg.sender] < amount) revert InsufficientBalance();
        
        // Effects (update state before external call)
        userBalances[msg.sender] -= amount;
        totalFunds -= amount;
        
        // Interactions (external call last)
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        if (!success) revert TransferFailed();
        
        emit FundsWithdrawn(msg.sender, amount, block.timestamp);
    }
    
    /**
     * @notice Manage user authorization with proper access control
     * @param user Address to authorize or revoke
     * @param authorize True to authorize, false to revoke
     * @dev Only owner can manage user permissions
     */
    function manageUserAccess(address user, bool authorize) 
        external 
        onlyOwner 
        notZeroAddress(user) 
    {
        // Prevent owner from revoking their own access
        require(user != owner || authorize, "Owner cannot revoke their own access");
        
        authorizedUsers[user] = authorize;
        
        if (authorize) {
            emit UserAuthorized(user, msg.sender, block.timestamp);
        } else {
            emit UserRevoked(user, msg.sender, block.timestamp);
        }
    }
    
    /**
     * @notice Transfer ownership with proper validation
     * @param newOwner Address of the new owner
     * @dev Implements secure ownership transfer pattern
     */
    function transferOwnership(address newOwner) 
        external 
        onlyOwner 
        notZeroAddress(newOwner) 
    {
        require(newOwner != owner, "New owner cannot be the same as current owner");
        
        address previousOwner = owner;
        owner = newOwner;
        
        // Ensure new owner is authorized
        authorizedUsers[newOwner] = true;
        
        emit OwnershipTransferred(previousOwner, newOwner);
        emit UserAuthorized(newOwner, previousOwner, block.timestamp);
    }
    
    // View functions
    function getUserBalance(address user) external view returns (uint256) {
        return userBalances[user];
    }
    
    function isAuthorized(address user) external view returns (bool) {
        return authorizedUsers[user];
    }
    
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    // Emergency functions (only owner)
    function emergencyPause() external onlyOwner {
        locked = true;
    }
    
    function emergencyUnpause() external onlyOwner {
        locked = false;
    }
    
    // Fallback and receive functions
    receive() external payable {
        userBalances[msg.sender] += msg.value;
        totalFunds += msg.value;
        emit FundsDeposited(msg.sender, msg.value, block.timestamp);
    }
    
    fallback() external payable {
        revert("Function not found");
    }
}



