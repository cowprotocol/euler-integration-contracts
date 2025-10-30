// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Order} from "cow/libraries/GPv2Order.sol";

import {EthereumVaultConnector} from "evc/EthereumVaultConnector.sol";
import {EVaultTestBase} from "lib/euler-vault-kit/test/unit/evault/EVaultTestBase.t.sol";
import {IEVault, IVault, IERC4626, IERC20} from "euler-vault-kit/src/EVault/IEVault.sol";

import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
import {CowSettlement} from "../../src/vendor/CowWrapper.sol";

import {MilkSwap} from "./MilkSwap.sol";

// intermediate contrct that acts as solver and creates a "batched" transaction
contract Solver {
    function runBatch(address[] memory targets, bytes[] memory datas) external {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success,) = targets[i].call(datas[i]);
            require(success, "Solver: call failed");
        }
    }
}

contract CowBaseTest is EVaultTestBase {
    uint256 mainnetFork;
    uint256 constant BLOCK_NUMBER = 22546006;
    string forkRpcUrl = vm.envOr("FORK_RPC_URL", string(""));

    //address constant solver = 0x7E2eF26AdccB02e57258784957922AEEFEe807e5; // quasilabs
    address constant ALLOW_LIST_MANAGER = 0xA03be496e67Ec29bC62F01a428683D7F9c204930;

    address constant SUSDS = 0xa3931d71877C0E7a3148CB7Eb4463524FEc27fbD;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    // Vaults
    address internal constant ESUSDS = 0x1e548CfcE5FCF17247E024eF06d32A01841fF404;
    address internal constant EWETH = 0xD8b27CF359b7D15710a5BE299AF6e7Bf904984C2;

    address payable constant REAL_EVC = payable(0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383);
    address internal swapVerifier = 0xae26485ACDDeFd486Fe9ad7C2b34169d360737c7;

    CowSettlement constant COW_SETTLEMENT = CowSettlement(payable(0x9008D19f58AAbD9eD0D60971565AA8510560ab41));

    MilkSwap public milkSwap;
    address user;
    uint256 privateKey = 123;

    Solver internal solver;

    function setUp() public virtual override {
        super.setUp();
        solver = new Solver();

        if (bytes(forkRpcUrl).length == 0) {
            revert("Must supply FORK_RPC_URL");
        }

        mainnetFork = vm.createSelectFork(forkRpcUrl);
        vm.rollFork(BLOCK_NUMBER);

        evc = EthereumVaultConnector(REAL_EVC);

        user = vm.addr(privateKey);

        // Add wrapper and our fake solver as solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(address(COW_SETTLEMENT.authenticator()));
        address manager = allowList.manager();
        // vm.deal(address(manager), 1e18);
        vm.startPrank(manager);
        allowList.addSolver(address(solver));
        vm.stopPrank();

        // Setup some liquidity for MilkSwap
        milkSwap = new MilkSwap();
        deal(SUSDS, address(milkSwap), 10000e18); // Add SUSDS to MilkSwap
        deal(WETH, address(milkSwap), 10000e18); // Add WETH to MilkSwap
        milkSwap.setPrice(WETH, 1000e18); // 1 ETH = 1,000 USD
        milkSwap.setPrice(SUSDS, 1e18); // 1 USDS = 1 USD

        // Set the approval for MilkSwap in the settlement as a convenience
        vm.startPrank(address(COW_SETTLEMENT));
        IERC20(WETH).approve(address(milkSwap), type(uint256).max);
        IERC20(SUSDS).approve(address(milkSwap), type(uint256).max);

        IERC20(ESUSDS).approve(address(ESUSDS), type(uint256).max);
        IERC20(EWETH).approve(address(EWETH), type(uint256).max);

        vm.stopPrank();

        // User has approved WETH for COW Protocol
        address vaultRelayer = COW_SETTLEMENT.vaultRelayer();
        vm.prank(user);
        IERC20(WETH).approve(vaultRelayer, type(uint256).max);

        // Setup labels
        //vm.label(solver, "solver");
        vm.label(ALLOW_LIST_MANAGER, "allow list manager");
        vm.label(user, "user");
        vm.label(SUSDS, "SUSDS");
        vm.label(WETH, "WETH");
        vm.label(ESUSDS, "eSUSDS");
        vm.label(EWETH, "eWETH");
        vm.label(address(COW_SETTLEMENT), "cow settlement");
        vm.label(address(milkSwap), "milkswap");
    }

    function getEmptySettlement()
        public
        pure
        returns (
            IERC20[] memory tokens,
            uint256[] memory clearingPrices,
            CowSettlement.CowTradeData[] memory trades,
            CowSettlement.CowInteractionData[][3] memory interactions
        )
    {
        return (
            new IERC20[](0),
            new uint256[](0),
            new CowSettlement.CowTradeData[](0),
            [
                new CowSettlement.CowInteractionData[](0),
                new CowSettlement.CowInteractionData[](0),
                new CowSettlement.CowInteractionData[](0)
            ]
        );
    }

    function getOrderUid(address owner, GPv2Order.Data memory orderData) public view returns (bytes memory orderUid) {
        // Generate order digest using EIP-712
        bytes32 orderDigest = GPv2Order.hash(orderData, COW_SETTLEMENT.domainSeparator());

        // Create order UID by concatenating orderDigest, owner, and validTo
        return abi.encodePacked(orderDigest, address(owner), uint32(orderData.validTo));
    }

    function getSwapInteraction(address sellToken, address buyToken, uint256 sellAmount)
        public
        view
        returns (CowSettlement.CowInteractionData memory)
    {
        return CowSettlement.CowInteractionData({
            target: address(milkSwap),
            value: 0,
            callData: abi.encodeCall(MilkSwap.swap, (sellToken, buyToken, sellAmount))
        });
    }

    // NOTE: get skimInteraction has to be called after this
    function getDepositInteraction(address vault, uint256 sellAmount)
        public
        view
        returns (CowSettlement.CowInteractionData memory)
    {
        return CowSettlement.CowInteractionData({
            target: address(IEVault(vault).asset()),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (vault, sellAmount))
        });
    }

    function getWithdrawInteraction(address vault, uint256 sellAmount)
        public
        pure
        returns (CowSettlement.CowInteractionData memory)
    {
        return CowSettlement.CowInteractionData({
            target: vault,
            value: 0,
            callData: abi.encodeCall(IERC4626.withdraw, (sellAmount, address(COW_SETTLEMENT), address(COW_SETTLEMENT)))
        });
    }

    function getSkimInteraction() public pure returns (CowSettlement.CowInteractionData memory) {
        return CowSettlement.CowInteractionData({
            target: address(ESUSDS),
            value: 0,
            callData: abi.encodeCall(IVault.skim, (type(uint256).max, address(COW_SETTLEMENT)))
        });
    }

    function getTradeData(
        uint256 sellAmount,
        uint256 buyAmount,
        uint32 validTo,
        address owner,
        address receiver,
        bool isBuy
    ) public pure returns (CowSettlement.CowTradeData memory) {
        // Set flags for (pre-sign, FoK sell order)
        // See
        // https://github.com/cowprotocol/contracts/blob/08f8627d8427c8842ae5d29ed8b44519f7674879/src/contracts/libraries/GPv2Trade.sol#L89-L94
        uint256 flags = (3 << 5) | (isBuy ? 1 : 0); // 1100000

        return CowSettlement.CowTradeData({
            sellTokenIndex: 0,
            buyTokenIndex: 1,
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
    }

    function getTokensAndPrices() public pure returns (address[] memory tokens, uint256[] memory clearingPrices) {
        tokens = new address[](2);
        tokens[0] = WETH;
        tokens[1] = ESUSDS;

        clearingPrices = new uint256[](2);
        clearingPrices[0] = 999; // WETH price (if it was against SUSD then 1000)
        clearingPrices[1] = 1; // eSUSDS price
    }
}
