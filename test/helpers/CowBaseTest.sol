// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import {GPv2Signing} from "cow/mixins/GPv2Signing.sol";
import {GPv2Order} from "cow/libraries/GPv2Order.sol";
import {IERC20} from "cow/libraries/GPv2Trade.sol";

import {IEVC} from "evc/interfaces/IEthereumVaultConnector.sol";
import {EthereumVaultConnector} from "evc/EthereumVaultConnector.sol";
import {EVaultTestBase} from "lib/euler-vault-kit/test/unit/evault/EVaultTestBase.t.sol";
import {IVault} from "euler-vault-kit/src/EVault/IEVault.sol";

import {CowEvcWrapper} from "../../src/CowEvcWrapper.sol";
import {GPv2AllowListAuthentication} from "cow/GPv2AllowListAuthentication.sol";
import {CowEvcWrapper, GPv2Trade, GPv2Interaction} from "../../src/CowEvcWrapper.sol";
import {IGPv2Settlement} from "../../src/vendor/interfaces/IGPv2Settlement.sol";

import {MilkSwap} from "./MilkSwap.sol";
import {GPv2OrderHelper} from "./GPv2OrderHelper.sol";

import {console} from "forge-std/Test.sol";

// intermediate contrct that acts as solver and creates a "batched" transaction
contract Solver {
    function runBatch(address[] memory targets, bytes[] memory datas) external {
        for (uint256 i = 0; i < targets.length; i++) {
            targets[i].call(datas[i]);
        }
    }
}

contract CowBaseTest is EVaultTestBase {
    uint256 mainnetFork;
    uint256 BLOCK_NUMBER = 22546006;
    string FORK_RPC_URL = vm.envOr("FORK_RPC_URL", string(""));

    //address constant solver = 0x7E2eF26AdccB02e57258784957922AEEFEe807e5; // quasilabs
    address constant allowListManager = 0xA03be496e67Ec29bC62F01a428683D7F9c204930;

    address constant SUSDS = 0xa3931d71877C0E7a3148CB7Eb4463524FEc27fbD;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    // Vaults
    address internal eSUSDS = 0x1e548CfcE5FCF17247E024eF06d32A01841fF404;
    address internal eWETH = 0xD8b27CF359b7D15710a5BE299AF6e7Bf904984C2;

    address payable constant realEVC = payable(0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383);
    address internal swapVerifier = 0xae26485ACDDeFd486Fe9ad7C2b34169d360737c7;

    IGPv2Settlement constant cowSettlement = IGPv2Settlement(payable(0x9008D19f58AAbD9eD0D60971565AA8510560ab41));

    CowEvcWrapper public wrapper;
    MilkSwap public milkSwap;
    address user;
    uint256 privateKey = 123;

    GPv2OrderHelper helper;

    Solver internal solver;

    function setUp() public virtual override {
        super.setUp();
        helper = new GPv2OrderHelper();
        solver = new Solver();

        if (bytes(FORK_RPC_URL).length == 0) {
            revert("Must supply FORK_RPC_URL");
        }

        mainnetFork = vm.createSelectFork(FORK_RPC_URL);
        vm.rollFork(BLOCK_NUMBER);

        evc = EthereumVaultConnector(realEVC);

        user = vm.addr(privateKey);
        wrapper = new CowEvcWrapper(address(evc), payable(cowSettlement));

        // Add wrapper and our fake solver as solver
        GPv2AllowListAuthentication allowList = GPv2AllowListAuthentication(cowSettlement.authenticator());
        address manager = allowList.manager();
        // vm.deal(address(manager), 1e18);
        vm.startPrank(manager);
        allowList.addSolver(address(wrapper));
        allowList.addSolver(address(solver));
        vm.stopPrank();

        // Setup some liquidity for MilkSwap
        milkSwap = new MilkSwap(SUSDS);
        deal(SUSDS, address(milkSwap), 10000e18); // Add SUSDS to MilkSwap
        milkSwap.setPrice(WETH, 1000); // 1 ETH = 1,000 SUSDS

        // Set the approval for MilSwap in the settlement
        vm.prank(address(cowSettlement));
        IERC20(WETH).approve(address(milkSwap), type(uint256).max);

        // User has approved WETH for COW Protocol
        address vaultRelayer = cowSettlement.vaultRelayer();
        vm.prank(user);
        IERC20(WETH).approve(vaultRelayer, type(uint256).max);

        // Setup labels
        //vm.label(solver, "solver");
        vm.label(allowListManager, "allowListManager");
        vm.label(user, "user");
        vm.label(SUSDS, "SUSDS");
        vm.label(WETH, "WETH");
        vm.label(eSUSDS, "eSUSDS");
        vm.label(eWETH, "eWETH");
        vm.label(address(cowSettlement), "cowSettlement");
        vm.label(address(wrapper), "wrapper");
        vm.label(address(milkSwap), "milkSwap");
    }

    function getEmptySettlement()
        public
        pure
        returns (
            IERC20[] memory tokens,
            uint256[] memory clearingPrices,
            GPv2Trade.Data[] memory trades,
            GPv2Interaction.Data[][3] memory interactions
        )
    {
        return (
            new IERC20[](0),
            new uint256[](0),
            new GPv2Trade.Data[](0),
            [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](0)]
        );
    }

    function getOrderUid(address owner, GPv2Order.Data memory orderData) public view returns (bytes memory orderUid) {
        // Generate order digest using EIP-712
        bytes32 orderDigest = GPv2Order.hash(orderData, cowSettlement.domainSeparator());

        // Create order UID by concatenating orderDigest, owner, and validTo
        return abi.encodePacked(orderDigest, address(owner), uint32(orderData.validTo));
    }

    function getSwapInteraction(uint256 sellAmount) public view returns (GPv2Interaction.Data memory) {
        return GPv2Interaction.Data({
            target: address(milkSwap),
            value: 0,
            callData: abi.encodeCall(MilkSwap.swap, (WETH, SUSDS, sellAmount))
        });
    }

    function getDepositInteraction(uint256 buyAmount) public view returns (GPv2Interaction.Data memory) {
        return GPv2Interaction.Data({
            target: address(SUSDS),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (eSUSDS, buyAmount))
        });
    }

    function getSkimInteraction() public view returns (GPv2Interaction.Data memory) {
        return GPv2Interaction.Data({
            target: address(eSUSDS),
            value: 0,
            callData: abi.encodeCall(IVault.skim, (type(uint256).max, address(cowSettlement)))
        });
    }

    function getTradeData(uint256 sellAmount, uint256 buyAmount, uint32 validTo, address owner, address receiver)
        public
        pure
        returns (GPv2Trade.Data memory)
    {
        // Set flags for (pre-sign, FoK sell order)
        // See
        // https://github.com/cowprotocol/contracts/blob/08f8627d8427c8842ae5d29ed8b44519f7674879/src/contracts/libraries/GPv2Trade.sol#L89-L94
        uint256 flags = 3 << 5; // 1100000

        return GPv2Trade.Data({
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

    function getTokensAndPrices() public view returns (IERC20[] memory tokens, uint256[] memory clearingPrices) {
        tokens = new IERC20[](2);
        tokens[0] = IERC20(WETH);
        tokens[1] = IERC20(eSUSDS);

        clearingPrices = new uint256[](2);
        clearingPrices[0] = 999; // WETH price (if it was against SUSD then 1000)
        clearingPrices[1] = 1; // eSUSDS price
    }

    function getSwapSettlement(address owner, address receiver, uint256 sellAmount, uint256 buyAmount)
        public
        view
        returns (
            bytes memory orderUid,
            GPv2Order.Data memory orderData,
            IERC20[] memory tokens,
            uint256[] memory clearingPrices,
            GPv2Trade.Data[] memory trades,
            GPv2Interaction.Data[][3] memory interactions
        )
    {
        uint32 validTo = uint32(block.timestamp + 1 hours);

        // Create order data
        orderData = GPv2Order.Data({
            sellToken: IERC20(WETH),
            buyToken: IERC20(eSUSDS),
            receiver: receiver,
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: validTo,
            appData: bytes32(0),
            feeAmount: 0,
            kind: GPv2Order.KIND_SELL,
            partiallyFillable: false,
            sellTokenBalance: GPv2Order.BALANCE_ERC20,
            buyTokenBalance: GPv2Order.BALANCE_ERC20
        });

        // Get order UID for the order
        orderUid = getOrderUid(owner, orderData);

        // Get trade data
        trades = new GPv2Trade.Data[](1);
        trades[0] = getTradeData(sellAmount, buyAmount, validTo, owner, orderData.receiver);

        // Get tokens and prices
        (tokens, clearingPrices) = getTokensAndPrices();

        // Setup interactions
        interactions = [new GPv2Interaction.Data[](0), new GPv2Interaction.Data[](3), new GPv2Interaction.Data[](0)];
        interactions[1][0] = getSwapInteraction(sellAmount);
        interactions[1][1] = getDepositInteraction(buyAmount + 1 ether);
        interactions[1][2] = getSkimInteraction();
        return (orderUid, orderData, tokens, clearingPrices, trades, interactions);
    }
}
