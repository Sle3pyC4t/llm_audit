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
    
    // 借贷相关状态变量
    mapping(address => uint256) public collateralAmount; // 用户存入的抵押品金额
    mapping(address => uint256) public loanAmount; // 用户借出的金额
    mapping(address => uint256) public loanTimestamp; // 借款时间戳
    mapping(address => bool) public cooldownActive; // 用户是否在冷却期
    mapping(address => uint256) public lastRepaidTimestamp; // 最后还款时间
    
    uint256 public loanDuration = 7 days; // 贷款期限
    uint256 public collateralRatio = 150; // 抵押率 (150表示150%)
    uint256 public interestRate = 5; // 年化利率 (5表示5%)
    
    // 签名相关变量
    mapping(address => uint256) public withdrawNonces; // 用于提款签名的nonce
    
    // 交易所相关变量
    mapping(address => uint256) public tokenBalance; // LP兑换另一个代币的余额
    
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
    
    // 漏洞1: 借贷功能 - 提供抵押品获取贷款
    // 漏洞点：没有最小借款额限制，可能导致小额贷款没有清算激励
    function provideLoan(uint256 collateralValue) public {
        require(balanceOf[msg.sender] >= collateralValue, "Insufficient balance for collateral");
        
        // 计算可以借出的金额 (抵押品价值的60%)
        uint256 loanValue = (collateralValue * 100) / collateralRatio;
        
        // 扣除抵押品
        balanceOf[msg.sender] -= collateralValue;
        collateralAmount[msg.sender] += collateralValue;
        
        // 提供贷款
        loanAmount[msg.sender] += loanValue;
        balanceOf[msg.sender] += loanValue;
        
        // 记录贷款时间
        loanTimestamp[msg.sender] = block.timestamp;
        lastRepaidTimestamp[msg.sender] = block.timestamp;
    }
    
    // 漏洞2: 还款功能
    // 漏洞点：还款时间计算错误，可能导致用户在贷款期限内被清算
    function repayLoan(uint256 amount) public {
        require(loanAmount[msg.sender] > 0, "No active loan");
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        
        // 还款处理
        if (amount > loanAmount[msg.sender]) {
            amount = loanAmount[msg.sender];
        }
        
        balanceOf[msg.sender] -= amount;
        loanAmount[msg.sender] -= amount;
        
        // 更新最后还款时间
        // 漏洞：不管还款金额多少，都更新lastRepaidTimestamp
        // 即使用户只偿还了1 wei，也会重置还款时间计数器
        lastRepaidTimestamp[msg.sender] = block.timestamp;
        
        // 如果完全还清了贷款，返还抵押品
        if (loanAmount[msg.sender] == 0) {
            uint256 collateral = collateralAmount[msg.sender];
            collateralAmount[msg.sender] = 0;
            balanceOf[msg.sender] += collateral;
        }
    }
    
    // 漏洞3: 清算功能
    // 漏洞点：缺乏清算激励和不支持部分清算
    function liquidate(address borrower) public {
        // 检查是否满足清算条件
        require(isLiquidatable(borrower), "Position not liquidatable");
        
        // 检查借款人是否处于冷却期
        // 漏洞：可以被借款人操控，通过activateCooldown提前进入冷却期
        require(!cooldownActive[borrower], "Borrower in cooldown period");
        
        uint256 debt = loanAmount[borrower];
        uint256 collateral = collateralAmount[borrower];
        
        // 漏洞：清算者必须一次性还清所有债务，没有部分清算机制
        require(balanceOf[msg.sender] >= debt, "Insufficient balance to liquidate");
        
        // 漏洞：没有清算奖励，对清算人没有经济激励
        balanceOf[msg.sender] -= debt;
        loanAmount[borrower] = 0;
        
        // 将抵押品转给清算人
        balanceOf[msg.sender] += collateral;
        collateralAmount[borrower] = 0;
    }
    
    // 检查用户是否可以被清算
    function isLiquidatable(address borrower) public view returns (bool) {
        if (loanAmount[borrower] == 0) return false;
        
        // 漏洞：清算条件错误 - 即使还款及时也可能被清算
        // 如果贷款期限为7天，而这里检查的是自借款开始后的3天
        uint256 gracePeriod = 3 days; 
        
        // 漏洞：用借款时间而非最后还款时间计算，可能导致刚借款就被清算
        return block.timestamp > loanTimestamp[borrower] + gracePeriod;
    }
    
    // 漏洞4: 冷却期功能 - 用户可以主动启用冷却期防止清算
    // 漏洞点：允许用户在即将被清算时激活冷却期，阻止清算
    function activateCooldown() public {
        require(loanAmount[msg.sender] > 0, "No active loan");
        cooldownActive[msg.sender] = true;
        
        // 冷却期持续2小时
        // 需要在其他地方实现cooldown结束逻辑，这里忽略
    }
    
    // 漏洞5: 签名提款功能
    // 漏洞点：缺少nonce导致签名可重放
    function withdrawWithSignature(uint256 amount, bytes memory signature) public {
        // 恢复签名者地址
        bytes32 message = keccak256(abi.encodePacked(msg.sender, amount));
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        
        address signer = recoverSigner(messageHash, signature);
        require(signer == owner, "Invalid signature");
        
        // 漏洞：没有使用nonce，相同签名可以重复使用
        // 应该使用: bytes32 message = keccak256(abi.encodePacked(msg.sender, amount, withdrawNonces[msg.sender]++));
        
        // 执行提款
        require(balanceOf[address(this)] >= amount, "Insufficient contract balance");
        balanceOf[address(this)] -= amount;
        balanceOf[msg.sender] += amount;
    }
    
    // 从签名中恢复签名者地址
    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        if (v < 27) {
            v += 27;
        }
        
        return ecrecover(messageHash, v, r, s);
    }
    
    // 漏洞6: 代币交换功能
    // 漏洞点：缺少滑点和截止时间保护
    function swapTokens(uint256 amountIn, address tokenOut) public returns (uint256) {
        require(balanceOf[msg.sender] >= amountIn, "Insufficient balance");
        
        // 计算能得到多少tokenOut (这里简化为1:1交换)
        uint256 amountOut = amountIn;
        
        // 漏洞1: 没有滑点保护，可能被夹击攻击
        // 漏洞2: 没有截止时间参数，交易可能在未来不利价格执行
        // 应该加上: require(amountOut >= minAmountOut, "Slippage too high");
        // 应该加上: require(block.timestamp <= deadline, "Transaction expired");
        
        // 执行交换
        balanceOf[msg.sender] -= amountIn;
        tokenBalance[msg.sender] += amountOut;
        
        return amountOut;
    }
    
    // Function to receive Ether
    receive() external payable {}
} 