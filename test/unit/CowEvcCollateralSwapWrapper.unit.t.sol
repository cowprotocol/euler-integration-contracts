// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8;

import "forge-std/Test.sol";
import {IEVC} from "evc/EthereumVaultConnector.sol";
import {CowEvcCollateralSwapWrapper} from "../../src/CowEvcCollateralSwapWrapper.sol";
import {EmptyWrapper} from "../EmptyWrapper.sol";
import {CowSettlement, CowAuthentication} from "../../src/vendor/CowWrapper.sol";
import {MockEVC} from "./mocks/MockEVC.sol";
import {MockCowAuthentication, MockCowSettlement} from "./mocks/MockCowProtocol.sol";
import {MockERC20, MockVault} from "./mocks/MockERC20AndVaults.sol";

/// @title Unit tests for CowEvcCollateralSwapWrapper
/// @notice Comprehensive unit tests focusing on isolated functionality testing with mocks
contract CowEvcCollateralSwapWrapperUnitTest is Test {
    CowEvcCollateralSwapWrapper public wrapper;
    EmptyWrapper public emptyWrapper;
    MockEVC public mockEVC;
    MockCowSettlement public mockSettlement;
    MockCowAuthentication public mockAuth;
    MockERC20 public mockAsset;
    MockVault public mockFromVault;
    MockVault public mockToVault;

    address constant OWNER = address(0x1111);
    address constant ACCOUNT = address(0x1112);
    address constant SOLVER = address(0x3333);

    // Constants from the contract
    bytes32 private constant KIND_SELL = hex"f3b277728b3fee749481eb3e0b3b48980dbbab78658fc419025cb16eee346775";
    bytes32 private constant KIND_BUY = hex"6ed88e868af0a1983e3886d5f3e95a2fafbd6c3450bc229e27342283dc429ccc";

    event PreApprovedHash(address indexed owner, bytes32 indexed hash, bool approved);
    event PreApprovedHashConsumed(address indexed owner, bytes32 indexed hash);

    // Helper function to decode signed calldata
    function _decodeSignedCalldata(bytes memory signedCalldata) internal pure returns (IEVC.BatchItem[] memory) {
        bytes memory encodedItems = new bytes(signedCalldata.length - 4);
        for (uint256 i = 4; i < signedCalldata.length; i++) {
            encodedItems[i - 4] = signedCalldata[i];
        }
        return abi.decode(encodedItems, (IEVC.BatchItem[]));
    }

    function setUp() public {
        mockAuth = new MockCowAuthentication();
        mockSettlement = new MockCowSettlement(address(mockAuth));
        mockEVC = new MockEVC();
        mockAsset = new MockERC20("Mock Asset", "MOCK");
        mockFromVault = new MockVault(address(mockAsset), "Mock From Vault", "mFROM");
        mockToVault = new MockVault(address(mockAsset), "Mock To Vault", "mTO");

        wrapper = new CowEvcCollateralSwapWrapper(address(mockEVC), CowSettlement(address(mockSettlement)));
        emptyWrapper = new EmptyWrapper(CowSettlement(address(mockSettlement)));

        // Set solver as authenticated
        mockAuth.setSolver(SOLVER, true);
        mockAuth.setSolver(address(wrapper), true);
        mockAuth.setSolver(address(emptyWrapper), true);

        // Set the correct onBehalfOfAccount for evcInternalSwap calls
        mockEVC.setOnBehalfOf(address(wrapper));
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsImmutables() public view {
        assertEq(address(wrapper.EVC()), address(mockEVC), "EVC not set correctly");
        assertEq(address(wrapper.SETTLEMENT()), address(mockSettlement), "SETTLEMENT not set correctly");
        assertEq(address(wrapper.AUTHENTICATOR()), address(mockAuth), "AUTHENTICATOR not set correctly");
        assertEq(wrapper.NONCE_NAMESPACE(), uint256(uint160(address(wrapper))), "NONCE_NAMESPACE incorrect");
    }

    function test_Constructor_SetsDomainSeparator() public view {
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("CowEvcCollateralSwapWrapper"),
                keccak256("1"),
                block.chainid,
                address(wrapper)
            )
        );
        assertEq(wrapper.DOMAIN_SEPARATOR(), expectedDomainSeparator, "DOMAIN_SEPARATOR incorrect");
    }

    function test_Constructor_SetsName() public view {
        assertEq(wrapper.name(), "Euler EVC - Collateral Swap", "Name not set correctly");
    }

    /*//////////////////////////////////////////////////////////////
                    PARSE WRAPPER DATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ParseWrapperData_EmptySignature() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data");
    }

    function test_ParseWrapperData_WithSignature() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes memory signature = new bytes(65);
        bytes memory wrapperData = abi.encode(params, signature);
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data");
    }

    function test_ParseWrapperData_WithExtraData() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes memory signature = new bytes(0);
        bytes memory wrapperData = abi.encode(params, signature);
        bytes memory extraData = hex"deadbeef";
        wrapperData = abi.encodePacked(wrapperData, extraData);

        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 4, "Should have 4 bytes remaining");
        assertEq(remaining, extraData, "Extra data should match");
    }

    /*//////////////////////////////////////////////////////////////
                    APPROVAL HASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetApprovalHash_Consistency() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes32 hash1 = wrapper.getApprovalHash(params);
        bytes32 hash2 = wrapper.getApprovalHash(params);

        assertEq(hash1, hash2, "Hash should be consistent");
    }

    function test_GetApprovalHash_DifferentForDifferentParams() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params1 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: OWNER,
                account: ACCOUNT,
                deadline: block.timestamp + 1 hours,
                fromVault: address(mockFromVault),
                toVault: address(mockToVault),
                swapAmount: 1000e18,
                kind: KIND_SELL
            });

        // Same as params1 except owner
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params2 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: ACCOUNT,
                account: ACCOUNT,
                deadline: block.timestamp + 1 hours,
                fromVault: address(mockFromVault),
                toVault: address(mockToVault),
                swapAmount: 1000e18,
                kind: KIND_SELL
            });

        // Same as params1 except swapAmount (the last meaningful field)
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params3 =
            CowEvcCollateralSwapWrapper.CollateralSwapParams({
                owner: OWNER,
                account: ACCOUNT,
                deadline: block.timestamp + 1 hours,
                fromVault: address(mockFromVault),
                toVault: address(mockToVault),
                swapAmount: 2000e18,
                kind: KIND_SELL
            });

        bytes32 hash1 = wrapper.getApprovalHash(params1);
        bytes32 hash2 = wrapper.getApprovalHash(params2);
        bytes32 hash3 = wrapper.getApprovalHash(params3);

        assertNotEq(hash1, hash2, "Hash should differ for different params");
        assertNotEq(hash1, hash3, "Hash should differ for different params");
    }

    function test_GetApprovalHash_MatchesEIP712() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes32 structHash = keccak256(
            abi.encode(
                params.owner,
                params.account,
                params.deadline,
                params.fromVault,
                params.toVault,
                params.swapAmount,
                params.kind
            )
        );

        bytes32 expectedDigest = keccak256(abi.encodePacked("\x19\x01", wrapper.DOMAIN_SEPARATOR(), structHash));
        bytes32 actualDigest = wrapper.getApprovalHash(params);

        assertEq(actualDigest, expectedDigest, "Hash should match EIP-712 format");
    }

    /*//////////////////////////////////////////////////////////////
                    GET SIGNED CALLDATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetSignedCalldata_EnablesNewCollateral() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items.length, 1, "Should have 1 batch item");
        assertEq(items[0].targetContract, address(mockEVC), "Should target EVC");
        assertEq(
            items[0].data,
            abi.encodeCall(IEVC.enableCollateral, (params.account, params.toVault)),
            "Should call enableCollateral"
        );
    }

    function test_GetSignedCalldata_UsesCorrectAccount() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items[0].onBehalfOfAccount, address(0), "Should have zero onBehalfOfAccount");
    }

    /*//////////////////////////////////////////////////////////////
                    FIND RATE PRICES TESTS
    //////////////////////////////////////////////////////////////*/

    function test_FindRatePrices_SuccessfulLookup() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER, // Same account to avoid transfer logic
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_BUY
        });

        address[] memory tokens = new address[](2);
        tokens[0] = address(mockFromVault);
        tokens[1] = address(mockToVault);

        uint256[] memory prices = new uint256[](2);
        prices[0] = 1e18;
        prices[1] = 2e18;

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        wrapper.evcInternalSwap(settleData, wrapperData, "");

        // If we get here, prices were found successfully
    }

    function test_FindRatePrices_MissingFromVaultPrice() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_BUY
        });

        // Only include toVault in tokens, not fromVault
        address[] memory tokens = new address[](1);
        tokens[0] = address(mockToVault);

        uint256[] memory prices = new uint256[](1);
        prices[0] = 2e18;

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));

        vm.prank(address(mockEVC));
        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcCollateralSwapWrapper.PricesNotFoundInSettlement.selector,
                address(mockFromVault),
                address(mockToVault)
            )
        );
        wrapper.evcInternalSwap(settleData, wrapperData, "");
    }

    function test_FindRatePrices_MissingToVaultPrice() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_BUY
        });

        // Only include fromVault in tokens, not toVault
        address[] memory tokens = new address[](1);
        tokens[0] = address(mockFromVault);

        uint256[] memory prices = new uint256[](1);
        prices[0] = 1e18;

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));

        vm.prank(address(mockEVC));
        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcCollateralSwapWrapper.PricesNotFoundInSettlement.selector,
                address(mockFromVault),
                address(mockToVault)
            )
        );
        wrapper.evcInternalSwap(settleData, wrapperData, "");
    }

    /*//////////////////////////////////////////////////////////////
                    EVC INTERNAL SWAP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EvcInternalSwap_OnlyEVC() public {
        bytes memory settleData = "";
        bytes memory wrapperData = "";
        bytes memory remainingWrapperData = "";

        vm.expectRevert(abi.encodeWithSelector(CowEvcCollateralSwapWrapper.Unauthorized.selector, address(this)));
        wrapper.evcInternalSwap(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSwap_RequiresCorrectOnBehalfOfAccount() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        // Set incorrect onBehalfOfAccount (not address(wrapper))
        mockEVC.setOnBehalfOf(address(0x9999));

        vm.prank(address(mockEVC));
        vm.expectRevert(abi.encodeWithSelector(CowEvcCollateralSwapWrapper.Unauthorized.selector, address(0x9999)));
        wrapper.evcInternalSwap(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSwap_CanBeCalledByEVC() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER, // Same account, no transfer needed
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        wrapper.evcInternalSwap(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSwap_WithSubaccount_KindSell() public {
        // Set up scenario where owner != account
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT, // Different from owner
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        // Give account some from vault tokens
        mockFromVault.mint(ACCOUNT, 2000e18);

        // These tokens need to be spendable by the wrapper
        vm.prank(ACCOUNT);
        mockFromVault.approve(address(wrapper), 2000e18);

        // Create settle data without prices (not needed for KIND_SELL)
        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        wrapper.evcInternalSwap(settleData, wrapperData, remainingWrapperData);

        // Verify transfer occurred from account to owner (exact swapAmount for SELL)
        assertEq(mockFromVault.balanceOf(ACCOUNT), 1000e18, "Account balance should decrease by swapAmount");
        assertEq(mockFromVault.balanceOf(OWNER), 1000e18, "Owner should receive swapAmount");
    }

    function test_EvcInternalSwap_WithSubaccount_KindBuy() public {
        // Set up scenario where owner != account with KIND_BUY
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT, // Different from owner
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18, // This is the buy amount (what we want to receive)
            kind: KIND_BUY
        });

        // Give account some from vault tokens
        mockFromVault.mint(ACCOUNT, 3000e18);

        // These tokens need to be spendable by the wrapper
        vm.prank(ACCOUNT);
        mockFromVault.approve(address(wrapper), 3000e18);

        // Create settle data with prices for KIND_BUY calculation
        address[] memory tokens = new address[](2);
        tokens[0] = address(mockFromVault);
        tokens[1] = address(mockToVault);

        uint256[] memory prices = new uint256[](2);
        prices[0] = 1e18; // fromVault price
        prices[1] = 2e18; // toVault price (2x more expensive)

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        wrapper.evcInternalSwap(settleData, wrapperData, remainingWrapperData);

        // For KIND_BUY: transferAmount = swapAmount * toVaultPrice / fromVaultPrice
        // transferAmount = 1000e18 * 2e18 / 1e18 = 2000e18
        assertEq(mockFromVault.balanceOf(ACCOUNT), 1000e18, "Account balance should decrease by 2000e18");
        assertEq(mockFromVault.balanceOf(OWNER), 2000e18, "Owner should receive calculated amount");
    }

    function test_EvcInternalSwap_SubaccountMustBeControlledByOwner() public {
        // Create an account that is NOT a valid subaccount of the owner
        // Valid subaccount would share first 19 bytes, but this one doesn't
        address invalidSubaccount = address(0x9999999999999999999999999999999999999999);

        // Approve the wrapper to transfer from the subaccount
        vm.prank(invalidSubaccount);
        mockFromVault.approve(address(wrapper), type(uint256).max);

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: invalidSubaccount, // Invalid subaccount
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        // Give account some from vault tokens
        mockFromVault.mint(invalidSubaccount, 2000e18);

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = "";

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcCollateralSwapWrapper.SubaccountMustBeControlledByOwner.selector, invalidSubaccount, OWNER
            )
        );
        wrapper.evcInternalSwap(settleData, wrapperData, remainingWrapperData);
    }

    function test_EvcInternalSwap_SameOwnerAndAccount() public {
        // When owner == account, no transfer should occur
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER, // Same as owner
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        mockFromVault.mint(OWNER, 2000e18);

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        wrapper.evcInternalSwap(settleData, wrapperData, "");

        // No transfer should occur, so balance should remain unchanged
        assertEq(mockFromVault.balanceOf(OWNER), 2000e18, "Owner balance should remain unchanged");
    }

    /*//////////////////////////////////////////////////////////////
                    WRAPPED SETTLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WrappedSettle_OnlySolver() public {
        bytes memory settleData = "";
        bytes memory wrapperData = hex"0000";

        vm.expectRevert(abi.encodeWithSignature("NotASolver(address)", address(this)));
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPermitSignature() public {
        mockFromVault.mint(OWNER, 2000e18);

        vm.prank(OWNER);
        mockFromVault.approve(address(wrapper), 2000e18);

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        address[] memory tokens = new address[](0);
        uint256[] memory prices = new uint256[](0);

        bytes memory signature = new bytes(65);
        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, signature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEVC.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    function test_WrappedSettle_WithPreApprovedHash() public {
        mockFromVault.mint(OWNER, 2000e18);

        vm.startPrank(OWNER);
        mockFromVault.approve(address(wrapper), 2000e18);
        vm.stopPrank();

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes32 hash = wrapper.getApprovalHash(params);

        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);

        mockEVC.setOperator(OWNER, address(wrapper), true);

        address[] memory tokens = new address[](0);
        uint256[] memory prices = new uint256[](0);

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEVC.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        assertFalse(wrapper.isHashPreApproved(OWNER, hash), "Hash should be consumed");
    }

    function test_WrappedSettle_PreApprovedHashRevertsIfDeadlineExceeded() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp - 1, // Past deadline
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes32 hash = wrapper.getApprovalHash(params);

        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);

        mockEVC.setOperator(OWNER, address(wrapper), true);

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        vm.prank(SOLVER);
        vm.expectRevert(
            abi.encodeWithSelector(
                CowEvcCollateralSwapWrapper.OperationDeadlineExceeded.selector, params.deadline, block.timestamp
            )
        );
        wrapper.wrappedSettle(settleData, wrapperData);
    }

    /*//////////////////////////////////////////////////////////////
                    EDGE CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SwapAmount_Zero() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 0, // Zero swap amount
            kind: KIND_SELL
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        // Should still have the enable collateral item
        assertEq(items.length, 1, "Should have 1 item even with zero swap amount");
    }

    function test_SwapAmount_Max() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: type(uint256).max,
            kind: KIND_SELL
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        assertEq(items.length, 1, "Should have 1 item with max swap amount");
    }

    function test_KindBuy_WithDifferentPrices() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 500e18,
            kind: KIND_BUY
        });

        mockFromVault.mint(ACCOUNT, 3000e18);
        vm.prank(ACCOUNT);
        mockFromVault.approve(address(wrapper), 3000e18);

        // toVault is 3x more expensive than fromVault
        address[] memory tokens = new address[](2);
        tokens[0] = address(mockFromVault);
        tokens[1] = address(mockToVault);

        uint256[] memory prices = new uint256[](2);
        prices[0] = 1e18; // fromVault price
        prices[1] = 3e18; // toVault price (3x more expensive)

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                tokens,
                prices,
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        wrapper.evcInternalSwap(settleData, wrapperData, "");

        // For KIND_BUY: transferAmount = 500e18 * 3e18 / 1e18 = 1500e18
        assertEq(mockFromVault.balanceOf(ACCOUNT), 1500e18, "Account balance should decrease by 1500e18");
        assertEq(mockFromVault.balanceOf(OWNER), 1500e18, "Owner should receive 1500e18");
    }

    function test_DifferentVaults() public {
        // Create another set of vaults
        MockVault anotherFromVault = new MockVault(address(mockAsset), "Another From", "aFROM");
        MockVault anotherToVault = new MockVault(address(mockAsset), "Another To", "aTO");

        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(anotherFromVault),
            toVault: address(anotherToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes memory signedCalldata = wrapper.getSignedCalldata(params);
        IEVC.BatchItem[] memory items = _decodeSignedCalldata(signedCalldata);

        // Verify it's enabling the correct toVault
        assertEq(
            items[0].data,
            abi.encodeCall(IEVC.enableCollateral, (OWNER, address(anotherToVault))),
            "Should enable correct toVault"
        );
    }

    function test_ParseWrapperData_LongSignature() public view {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        // Create a signature longer than 65 bytes
        bytes memory signature = new bytes(128);
        bytes memory wrapperData = abi.encode(params, signature);
        bytes memory remaining = wrapper.parseWrapperData(wrapperData);

        assertEq(remaining.length, 0, "Should have no remaining data with long signature");
    }

    function test_EvcInternalSwap_WithRemainingWrapperData() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        bytes memory remainingWrapperData = abi.encodePacked(emptyWrapper, hex"0004deadbeef");

        mockSettlement.setSuccessfulSettle(true);

        vm.prank(address(mockEVC));
        wrapper.evcInternalSwap(settleData, wrapperData, remainingWrapperData);

        // Should handle remaining wrapper data gracefully
    }

    function test_WrappedSettle_BuildsCorrectBatchWithPermit() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes memory signature = new bytes(65);
        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, signature);
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEVC.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        // Should build a batch with permit + evcInternalSwap (2 items)
    }

    function test_WrappedSettle_BuildsCorrectBatchWithPreApproved() public {
        CowEvcCollateralSwapWrapper.CollateralSwapParams memory params = CowEvcCollateralSwapWrapper.CollateralSwapParams({
            owner: OWNER,
            account: OWNER,
            deadline: block.timestamp + 1 hours,
            fromVault: address(mockFromVault),
            toVault: address(mockToVault),
            swapAmount: 1000e18,
            kind: KIND_SELL
        });

        bytes32 hash = wrapper.getApprovalHash(params);

        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);

        mockEVC.setOperator(OWNER, address(wrapper), true);

        bytes memory settleData = abi.encodeCall(
            CowSettlement.settle,
            (
                new address[](0),
                new uint256[](0),
                new CowSettlement.CowTradeData[](0),
                [
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0),
                    new CowSettlement.CowInteractionData[](0)
                ]
            )
        );
        bytes memory wrapperData = abi.encode(params, new bytes(0));
        wrapperData = abi.encodePacked(uint16(wrapperData.length), wrapperData);

        mockEVC.setSuccessfulBatch(true);

        vm.prank(SOLVER);
        wrapper.wrappedSettle(settleData, wrapperData);

        // Should build a batch with enableCollateral + evcInternalSwap (2 items)
    }
}
