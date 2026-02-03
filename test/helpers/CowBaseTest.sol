// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order} from "cow/libraries/GPv2Order.sol";
import {IERC20 as CowERC20} from "cow/interfaces/IERC20.sol";

import {EthereumVaultConnector} from "evc/EthereumVaultConnector.sol";
import {Test} from "forge-std/Test.sol";
import {IEVault, IERC4626, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
import {ICowSettlement} from "../../src/CowWrapper.sol";

import {MilkSwap} from "./MilkSwap.sol";

contract CowBaseTest is Test {
    uint256 mainnetFork;
    uint256 constant BLOCK_NUMBER = 22546006;
    string forkRpcUrl = vm.envOr("FORK_RPC_URL", string(""));

    //address constant solver = 0x7E2eF26AdccB02e57258784957922AEEFEe807e5; // quasilabs
    address constant ALLOW_LIST_MANAGER = 0xA03be496e67Ec29bC62F01a428683D7F9c204930;

    // Tokens (Assets for the below vaults)
    IERC20 constant USDS = IERC20(0xdC035D45d973E3EC169d2276DDab16f1e407384F);
    IERC20 constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 constant WBTC = IERC20(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);

    // Vaults
    IEVault internal constant EUSDS = IEVault(0x07F9A54Dc5135B9878d6745E267625BF0E206840);
    IEVault internal constant EWETH = IEVault(0xD8b27CF359b7D15710a5BE299AF6e7Bf904984C2);
    IEVault internal constant EWBTC = IEVault(0x998D761eC1BAdaCeb064624cc3A1d37A46C88bA4);

    ICowSettlement constant COW_SETTLEMENT = ICowSettlement(payable(0x9008D19f58AAbD9eD0D60971565AA8510560ab41));

    EthereumVaultConnector constant EVC = EthereumVaultConnector(payable(0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383));

    MilkSwap public milkSwap;
    address user;
    address user2;
    address user3;
    address account;
    address account2 = address(uint160(user2) ^ 1);
    address account3 = address(uint160(user3) ^ 1);
    uint256 privateKey;
    uint256 privateKey2;
    uint256 privateKey3;

    function setUp() public virtual {
        vm.skip(bytes(forkRpcUrl).length == 0);

        mainnetFork = vm.createSelectFork(forkRpcUrl);
        vm.rollFork(BLOCK_NUMBER);

        (user, privateKey) = makeAddrAndKey("user");

        // Certain specialized tests could use these additional users
        (user2, privateKey2) = makeAddrAndKey("user 2");
        (user3, privateKey3) = makeAddrAndKey("user 3");

        account = address(uint160(user) ^ 1);
        account2 = address(uint160(user2) ^ 1);
        account3 = address(uint160(user3) ^ 1);

        // Add test contract as solver so we can call wrappedSettle directly
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(COW_SETTLEMENT.authenticator()));
        address manager = allowList.manager();
        // vm.deal(address(manager), 1e18);
        vm.startPrank(manager);
        allowList.addSolver(address(this));
        vm.stopPrank();

        // Setup some liquidity for MilkSwap
        milkSwap = new MilkSwap();
        deal(address(USDS), address(milkSwap), 100000e18); // Add USDS to MilkSwap
        deal(address(WETH), address(milkSwap), 100000e18); // Add WETH to MilkSwap
        deal(address(WBTC), address(milkSwap), 100000e8); // Add WBTC to MilkSwap (8 decimals)
        milkSwap.setPrice(WETH, 2500e18); // 1 ETH = 2,500 USD
        milkSwap.setPrice(USDS, 1e18); // 1 USDS = 1 USD
        milkSwap.setPrice(WBTC, 100000e18 * 1e10); // 1 BTC = 100,000 USD (8 decimals)

        // deal small amount to the settlement contract that serve as buffer (just makes tests easier...)
        deal(address(USDS), address(COW_SETTLEMENT), 200e18);
        deal(address(WETH), address(COW_SETTLEMENT), 0.1e18);
        deal(address(WBTC), address(COW_SETTLEMENT), 0.002e8);
        deal(address(EUSDS), address(COW_SETTLEMENT), 200e18);
        deal(address(EWETH), address(COW_SETTLEMENT), 0.1e18);
        deal(address(EWBTC), address(COW_SETTLEMENT), 0.002e8);

        // Set the approval for MilkSwap in the settlement as a convenience
        vm.startPrank(address(COW_SETTLEMENT));
        WETH.approve(address(milkSwap), type(uint256).max);
        USDS.approve(address(milkSwap), type(uint256).max);
        WBTC.approve(address(milkSwap), type(uint256).max);

        USDS.approve(address(EUSDS), type(uint256).max);
        WETH.approve(address(EWETH), type(uint256).max);
        WBTC.approve(address(EWBTC), type(uint256).max);

        vm.stopPrank();

        // User has approved WETH for COW Protocol
        address vaultRelayer = COW_SETTLEMENT.vaultRelayer();
        vm.prank(user);
        WETH.approve(vaultRelayer, type(uint256).max);

        // Setup labels
        //vm.label(solver, "solver");
        vm.label(ALLOW_LIST_MANAGER, "allow list manager");
        vm.label(user, "user");
        vm.label(user2, "user 2");
        vm.label(user3, "user 3");
        vm.label(account, "account 1");
        vm.label(account2, "account 2");
        vm.label(account3, "account 3");
        vm.label(address(USDS), "USDS");
        vm.label(address(WETH), "WETH");
        vm.label(address(WBTC), "WBTC");
        vm.label(address(EUSDS), "eUSDS");
        vm.label(address(EWETH), "eWETH");
        vm.label(address(EWBTC), "eWBTC");
        vm.label(address(COW_SETTLEMENT), "CoW");
        vm.label(address(COW_SETTLEMENT.authenticator()), "CoW Auth");
        vm.label(address(COW_SETTLEMENT.vaultRelayer()), "CoW Vault Relayer");
        vm.label(address(EVC), "EVC");
        vm.label(address(milkSwap), "MilkSwap");
    }

    function getEmptySettlement()
        public
        pure
        returns (
            address[] memory tokens,
            uint256[] memory clearingPrices,
            ICowSettlement.Trade[] memory trades,
            ICowSettlement.Interaction[][3] memory interactions
        )
    {
        return (
            new address[](0),
            new uint256[](0),
            new ICowSettlement.Trade[](0),
            [
                new ICowSettlement.Interaction[](0),
                new ICowSettlement.Interaction[](0),
                new ICowSettlement.Interaction[](0)
            ]
        );
    }

    function getOrderUid(address owner, GPv2Order.Data memory orderData) public view returns (bytes memory orderUid) {
        // Generate order digest using EIP-712
        bytes32 orderDigest = GPv2Order.hash(orderData, COW_SETTLEMENT.domainSeparator());

        // Create order UID by concatenating orderDigest, owner, and validTo
        return abi.encodePacked(orderDigest, address(owner), uint32(orderData.validTo));
    }

    function getSwapInteraction(IERC20 sellToken, IERC20 buyToken, uint256 sellAmount)
        public
        view
        returns (ICowSettlement.Interaction memory)
    {
        return ICowSettlement.Interaction({
            target: address(milkSwap),
            value: 0,
            callData: abi.encodeCall(MilkSwap.swap, (sellToken, buyToken, sellAmount))
        });
    }

    function getDepositInteraction(IEVault vault, uint256 sellAmount)
        public
        pure
        returns (ICowSettlement.Interaction memory)
    {
        return ICowSettlement.Interaction({
            target: address(vault),
            value: 0,
            callData: abi.encodeCall(IERC4626.deposit, (sellAmount, address(COW_SETTLEMENT)))
        });
    }

    function getWithdrawInteraction(IEVault vault, uint256 sellAmount)
        public
        pure
        returns (ICowSettlement.Interaction memory)
    {
        return ICowSettlement.Interaction({
            target: address(vault),
            value: 0,
            callData: abi.encodeCall(IERC4626.withdraw, (sellAmount, address(COW_SETTLEMENT), address(COW_SETTLEMENT)))
        });
    }

    function setupCowOrder(
        address[] memory tokens,
        uint256 sellTokenIndex,
        uint256 buyTokenIndex,
        uint256 sellAmount,
        uint256 buyAmount,
        uint32 validTo,
        address owner,
        address receiver,
        bool isBuy
    ) public returns (ICowSettlement.Trade memory trade, GPv2Order.Data memory order, bytes memory orderId) {
        // Set flags for (pre-sign, FoK sell order)
        // See
        // https://github.com/cowprotocol/contracts/blob/08f8627d8427c8842ae5d29ed8b44519f7674879/src/contracts/libraries/GPv2Trade.sol#L89-L94
        uint256 flags = (3 << 5) | (isBuy ? 1 : 0); // 1100000

        trade = ICowSettlement.Trade({
            sellTokenIndex: sellTokenIndex,
            buyTokenIndex: buyTokenIndex,
            receiver: receiver,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            appData: bytes32(0),
            feeAmount: 0,
            flags: flags,
            executedAmount: 0,
            signature: abi.encodePacked(owner)
        });

        // Extract order from trade (manually applying GPv2Trade.extractOrder logic)
        order = GPv2Order.Data({
            sellToken: CowERC20(tokens[trade.sellTokenIndex]),
            buyToken: CowERC20(tokens[trade.buyTokenIndex]),
            receiver: trade.receiver,
            sellAmount: trade.sellAmount,
            buyAmount: trade.buyAmount,
            validTo: trade.validTo,
            appData: trade.appData,
            feeAmount: trade.feeAmount,
            kind: isBuy ? GPv2Order.KIND_BUY : GPv2Order.KIND_SELL,
            partiallyFillable: false, // FoK orders are not partially fillable
            sellTokenBalance: GPv2Order.BALANCE_ERC20,
            buyTokenBalance: GPv2Order.BALANCE_ERC20
        });

        orderId = getOrderUid(owner, order);

        // we basically always want to sign the order id
        vm.prank(owner);
        COW_SETTLEMENT.setPreSignature(orderId, true);
    }

    /// @notice Setup CoW order with EIP-1271 signature using Inbox as the order owner
    /// @dev Creates an order where the Inbox contract signs on behalf of the user.
    /// This is used for the CowEvcClosePositionWrapper
    /// Note: to reduce params, inboxForUser is assumed to be same as receiver
    function setupCowOrderEip1271(
        address[] memory tokens,
        uint256 sellTokenIndex,
        uint256 buyTokenIndex,
        uint256 sellAmount,
        uint256 buyAmount,
        uint32 validTo,
        address receiver,
        bool isBuy,
        uint256 signerPrivateKey
    ) public view returns (ICowSettlement.Trade memory trade, GPv2Order.Data memory order, bytes memory orderId) {
        // Use EIP-1271 signature type (1 << 6)
        uint256 flags = (1 << 6) | (isBuy ? 1 : 0); // EIP-1271 signature type

        order = GPv2Order.Data({
            sellToken: CowERC20(tokens[sellTokenIndex]),
            buyToken: CowERC20(tokens[buyTokenIndex]),
            receiver: receiver,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            appData: bytes32(0),
            feeAmount: 0,
            kind: isBuy ? GPv2Order.KIND_BUY : GPv2Order.KIND_SELL,
            partiallyFillable: false,
            sellTokenBalance: GPv2Order.BALANCE_ERC20,
            buyTokenBalance: GPv2Order.BALANCE_ERC20
        });

        // Create the EIP-1271 signature
        // the "Inbox" for the user is assumed to be the same as the receiver
        bytes memory eip1271Signature = _createEip1271Signature(receiver, order, signerPrivateKey);

        // Create the trade with EIP-1271 signature
        trade = ICowSettlement.Trade({
            sellTokenIndex: sellTokenIndex,
            buyTokenIndex: buyTokenIndex,
            receiver: receiver,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            appData: bytes32(0),
            feeAmount: 0,
            flags: flags,
            executedAmount: 0,
            signature: eip1271Signature
        });

        orderId = getOrderUid(receiver, order);
    }

    /// @notice Create EIP-1271 signature for a CoW order
    /// @dev Signs the order digest with the user's private key and returns the signature
    function _createEip1271Signature(address inboxForUser, GPv2Order.Data memory orderData, uint256 userPrivateKey)
        internal
        view
        returns (bytes memory signature)
    {
        // Compute the order digest
        bytes32 orderDigest = GPv2Order.hash(orderData, COW_SETTLEMENT.domainSeparator());

        // Sign the digest with the user's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, orderDigest);

        // Return the signature as packed bytes (inbox || r || s || v) (in CoW, first 20 bytes is the 1271 isValidSignature verifier)
        return abi.encodePacked(inboxForUser, r, s, v);
    }

    function getTokensAndPrices() public view returns (address[] memory tokens, uint256[] memory clearingPrices) {
        tokens = new address[](4);
        tokens[0] = address(USDS);
        tokens[1] = address(WETH);
        tokens[2] = address(EUSDS);
        tokens[3] = address(EWETH);

        clearingPrices = new uint256[](4);
        clearingPrices[0] = 1 ether; // USDS price
        clearingPrices[1] = 2500 ether; // WETH price
        clearingPrices[2] = IERC4626(EUSDS).convertToAssets(clearingPrices[0]); // eUSDS price
        clearingPrices[3] = IERC4626(EWETH).convertToAssets(clearingPrices[1]); // eWETH price
    }

    /// @notice Helper to set up a leveraged position for any user
    /// @dev More flexible version that accepts owner, account, and vault parameters
    /// The proceeds of the `borrow` are *NOT* deposited in the account for convienience of setup.
    /// So make sure that `collateralAmount` is margin + borrowValue if that is something you care about.
    function setupLeveragedPositionFor(
        address owner,
        address ownerAccount,
        IEVault collateralVault,
        IEVault borrowVault,
        uint256 collateralAmount,
        uint256 borrowAmount
    ) internal {
        IERC20 collateralAsset = IERC20(collateralVault.asset());

        deal(address(collateralAsset), owner, collateralAmount);

        vm.startPrank(owner);
        collateralAsset.approve(address(collateralVault), type(uint256).max);
        EVC.enableCollateral(ownerAccount, address(collateralVault));
        EVC.enableController(ownerAccount, address(borrowVault));
        collateralVault.deposit(collateralAmount, ownerAccount);
        vm.stopPrank();

        vm.prank(ownerAccount);
        borrowVault.borrow(borrowAmount, address(1));
    }

    /// @notice Encode wrapper data with length prefix
    /// @dev Takes already abi.encoded params and signature
    function encodeWrapperData(bytes memory paramsAndSignature) internal pure returns (bytes memory) {
        return abi.encodePacked(uint16(paramsAndSignature.length), paramsAndSignature);
    }
}
