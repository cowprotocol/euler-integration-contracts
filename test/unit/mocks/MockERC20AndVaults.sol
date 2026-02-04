// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";

import {MockEVC} from "./MockEVC.sol";

/// @title MockERC20
/// @notice Mock ERC20 token for unit testing
contract MockERC20 is IERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 18;

    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;
    uint256 public override totalSupply;

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external virtual override returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external virtual override returns (bool) {
        require(balanceOf[msg.sender] >= amount, "ERC20Mock: insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external virtual override returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            require(allowance[from][msg.sender] >= amount, "ERC20Mock: insufficient allowance");
            allowance[from][msg.sender] -= amount;
        }
        require(balanceOf[from] >= amount, "ERC20Mock: insufficient balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

    /// @title MockVault
    /// @notice Mock ERC4626 vault for unit testing
    contract MockVault is IERC4626, MockERC20 {
        address public immutable ASSET_ADDRESS;
        MockEVC public immutable EVC;

        constructor(MockEVC _evc, address _asset, string memory _name, string memory _symbol)
            MockERC20(_name, _symbol)
        {
            ASSET_ADDRESS = _asset;
            EVC = _evc;
        }

        function asset() external view override returns (address) {
            return ASSET_ADDRESS;
        }

        function totalAssets() external view override returns (uint256) {
            return totalSupply;
        }

        function convertToShares(uint256 assets) external pure override returns (uint256) {
            return assets;
        }

        function convertToAssets(uint256 shares) external pure override returns (uint256) {
            return shares;
        }

        function maxDeposit(address) external pure override returns (uint256) {
            return type(uint256).max;
        }

        function maxMint(address) external pure override returns (uint256) {
            return type(uint256).max;
        }

        function maxWithdraw(address owner) external view override returns (uint256) {
            return balanceOf[owner];
        }

        function maxRedeem(address owner) external view override returns (uint256) {
            return balanceOf[owner];
        }

        function previewDeposit(uint256 assets) external pure override returns (uint256) {
            return assets;
        }

        function previewMint(uint256 shares) external pure override returns (uint256) {
            return shares;
        }

        function previewWithdraw(uint256 assets) external pure override returns (uint256) {
            return assets;
        }

        function previewRedeem(uint256 shares) external pure override returns (uint256) {
            return shares;
        }

        function deposit(uint256 assets, address receiver) external override returns (uint256) {
            balanceOf[receiver] += assets;
            totalSupply += assets;
            return assets;
        }

        function mint(uint256 shares, address receiver) external override returns (uint256) {
            balanceOf[receiver] += shares;
            totalSupply += shares;
            return shares;
        }

        function withdraw(uint256 assets, address receiver, address owner) external override returns (uint256) {
            balanceOf[owner] -= assets;
            totalSupply -= assets;
            balanceOf[receiver] += assets;
            return assets;
        }

        function redeem(uint256 shares, address receiver, address owner) external override returns (uint256) {
            balanceOf[owner] -= shares;
            totalSupply -= shares;
            balanceOf[receiver] += shares;
            return shares;
        }

        function approve(address spender, uint256 amount) external override returns (bool) {
            address sender = msg.sender;
            if (sender == address(EVC)) {
                (sender,) = EVC.getCurrentOnBehalfOfAccount(address(0));
            }
            allowance[sender][spender] = amount;
            return true;
        }

        function transfer(address to, uint256 amount) external override returns (bool) {
            address sender = msg.sender;
            if (sender == address(EVC)) {
                (sender,) = EVC.getCurrentOnBehalfOfAccount(address(0));
            }
            require(balanceOf[sender] >= amount, "ERC20Mock: insufficient balance");
            balanceOf[sender] -= amount;
            balanceOf[to] += amount;
            return true;
        }

        function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
            address spender = msg.sender;
            if (spender == address(EVC)) {
                (spender,) = EVC.getCurrentOnBehalfOfAccount(address(0));
            }
            if (allowance[from][spender] != type(uint256).max) {
                require(allowance[from][spender] >= amount, "ERC20Mock: insufficient allowance");
                allowance[from][spender] -= amount;
            }
            require(balanceOf[from] >= amount, "ERC20Mock: insufficient balance");
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
            return true;
        }
    }

    /// @title MockBorrowVault
    /// @notice Mock borrowing vault for unit testing
    contract MockBorrowVault is MockVault, IBorrowing {
        mapping(address => uint256) public debts;
        uint256 public repayAmount;
        bool public repayAllWasCalled;

        constructor(MockEVC _evc, address _asset, string memory _name, string memory _symbol)
            MockVault(_evc, _asset, _name, _symbol)
        {}

        function setDebt(address account, uint256 amount) external {
            debts[account] = amount;
        }

        function setRepayAmount(uint256 amount) external {
            repayAmount = amount;
        }

        function debtOf(address account) external view override returns (uint256) {
            return debts[account];
        }

        function debtOfExact(address account) external view override returns (uint256) {
            return debts[account];
        }

        function repay(uint256 amount, address receiver) external override returns (uint256) {
            if (amount == type(uint256).max) {
                repayAllWasCalled = true;
                amount = debts[receiver];
            }

            if (repayAmount > 0) {
                amount = repayAmount;
            }

            debts[receiver] -= amount;

            // Transfer tokens from sender
            require(MockERC20(ASSET_ADDRESS).transferFrom(msg.sender, address(this), amount), "transfer failed");

            return amount;
        }

        function repayAllCalled() external view returns (bool) {
            return repayAllWasCalled;
        }

        function borrow(uint256 amount, address receiver) external override returns (uint256) {
            debts[msg.sender] += amount;
            MockERC20(ASSET_ADDRESS).mint(receiver, amount);
            return amount;
        }

        function pullDebt(uint256, address) external pure override {
            revert("Not implemented");
        }

        // Additional required functions from IBorrowing/IEVault
        function cash() external pure override returns (uint256) {
            return 0;
        }

        function dToken() external pure override returns (address) {
            return address(0);
        }

        function flashLoan(uint256, bytes calldata) external pure override {
            revert("Not implemented");
        }

        function interestAccumulator() external pure override returns (uint256) {
            return 1e27;
        }

        function interestRate() external pure override returns (uint256) {
            return 0;
        }

        function repayWithShares(uint256, address) external pure override returns (uint256, uint256) {
            revert("Not implemented");
        }

        function totalBorrows() external view override returns (uint256) {
            return totalSupply;
        }

        function totalBorrowsExact() external view override returns (uint256) {
            return totalSupply;
        }

        function touch() external pure override {
            // No-op for mock
        }
    }
