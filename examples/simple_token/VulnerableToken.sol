// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableToken
 * @dev This is an example ERC20 token contract
 * for demonstration purposes
 */
contract VulnerableToken {
    // Token basic information
    string public name = "Vulnerable Token";
    string public symbol = "VULN";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    
    // Account balance mapping
    mapping(address => uint256) public balanceOf;
    // Allowance mapping
    mapping(address => mapping(address => uint256)) public allowance;
    
    // Contract owner
    address public owner;
    
    // Locked status (for pausing transactions)
    bool public locked = false;
    
    // Constructor initialization
    constructor(uint256 initialSupply) {
        totalSupply = initialSupply * 10**uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        owner = msg.sender;
    }
    
    function transfer(address to, uint256 amount) public returns (bool) {
        if (locked) { 
            return false;
        }
        
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        
        return true;
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        
        allowance[from][msg.sender] -= amount;
        
        return true;
    }
    
    function withdrawFunds(uint256 amount) public {
        if (tx.origin == owner) {
            payable(msg.sender).transfer(amount);
        }
    }
    
    function donate() public payable {
        // Accept donations
    }
    
    function refund() public {
        require(address(this).balance > 0, "No funds to refund");
        
        uint256 toRefund = balanceOf[msg.sender];
        payable(msg.sender).call{value: toRefund}("");
        balanceOf[msg.sender] = 0;
    }
    
    function toggleLocked() public {
        locked = !locked;
    }
    
    function airdrop() public {
        uint256 randomAmount = uint256(keccak256(abi.encodePacked(block.timestamp, block.number, msg.sender))) % 1000;
        balanceOf[msg.sender] += randomAmount;
        totalSupply += randomAmount;
    }
    
    function burnTokens(uint256 amount) public {
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
    }
    
    // Function to receive Ether
    receive() external payable {}
} 