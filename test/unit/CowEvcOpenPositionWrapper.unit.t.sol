// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {IEVC} from "evc/EthereumVaultConnector.sol";
import {CowEvcOpenPositionWrapper} from "../../src/CowEvcOpenPositionWrapper.sol";
import {CowEvcBaseWrapper} from "../../src/CowEvcBaseWrapper.sol";
import {ICowSettlement} from "../../src/CowWrapper.sol";
import {UnitTestBase} from "./UnitTestBase.sol";
import {IERC4626, IBorrowing} from "euler-vault-kit/src/EVault/IEVault.sol";

// this is required because foundry doesn't have a cheatcode for override any transient storage.
contract TestableOpenPositionWrapper is CowEvcOpenPositionWrapper {
    constructor(address _evc, ICowSettlement _settlement) CowEvcOpenPositionWrapper(_evc, _settlement) {}

    function setExpectedEvcInternalSettleCall(bytes memory call) external {
        expectedEvcInternalSettleCallHash = keccak256(call);
    }
}

/// @title Unit tests for CowEvcOpenPositionWrapper
/// @notice Comprehensive unit tests focusing on isolated functionality testing with mocks
contract CowEvcOpenPositionWrapperUnitTest is UnitTestBase {
    uint256 constant DEFAULT_COLLATERAL_AMOUNT = 1000e18;
    uint256 constant DEFAULT_BORROW_AMOUNT = 500e18;

    /// @notice Get default OpenPositionParams for testing
    function _getDefaultParams() internal view returns (CowEvcOpenPositionWrapper.OpenPositionParams memory) {
        return CowEvcOpenPositionWrapper.OpenPositionParams({
            owner: OWNER,
            account: ACCOUNT,
            deadline: block.timestamp + 1 hours,
            collateralVault: COLLATERAL_VAULT,
            borrowVault: BORROW_VAULT,
            collateralAmount: DEFAULT_COLLATERAL_AMOUNT,
            borrowAmount: DEFAULT_BORROW_AMOUNT
        });
    }

    /// @notice Encode wrapper data with length prefix
    function _encodeWrapperData(CowEvcOpenPositionWrapper.OpenPositionParams memory params, bytes memory signature)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory wrapperData = abi.encode(params, signature);
        return abi.encodePacked(uint16(wrapperData.length), wrapperData);
    }

    function _prepareSuccessfulPermitSettlement()
        internal
        view
        override
        returns (bytes memory settleData, bytes memory wrapperData)
    {

        // A permit settlement is triggered by having signature data in `wrapperData`. 
        // For unit testing, we can just use 65 bytes of "zero" signtaure since we're not actually verifying it here.
        wrapperData = _encodeWrapperData(_getDefaultParams(), new bytes(65));
        settleData = _getEmptySettleData();
    }

    function _prepareSuccessfulPreSignSettlement()
        internal
        view
        override
        returns (bytes memory settleData, bytes memory wrapperData, bytes32 hash)
    {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

        // A pre-hash settlement is triggered by having 0-length signature data in `wrapperData`.
        wrapperData = _encodeWrapperData(params, new bytes(0));
        settleData = _getEmptySettleData();
        hash = CowEvcOpenPositionWrapper(address(wrapper)).getApprovalHash(params);
    }

    /// @notice Setup pre-approved hash flow
    function _setupPreApprovedHash(CowEvcOpenPositionWrapper.OpenPositionParams memory params)
        internal
        returns (bytes32)
    {
        bytes32 hash = CowEvcOpenPositionWrapper(address(wrapper)).getApprovalHash(params);
        vm.prank(OWNER);
        wrapper.setPreApprovedHash(hash, true);
        return hash;
    }

    function setUp() public override {
        super.setUp();

        wrapper = CowEvcBaseWrapper(
            new TestableOpenPositionWrapper(address(mockEvc), ICowSettlement(address(mockSettlement)))
        );
    }

    /*//////////////////////////////////////////////////////////////
                        CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsDomainSeparator() public view {
        bytes32 expectedDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("CowEvcOpenPositionWrapper"),
                keccak256("1"),
                block.chainid,
                address(wrapper)
            )
        );
        assertEq(wrapper.DOMAIN_SEPARATOR(), expectedDomainSeparator, "DOMAIN_SEPARATOR incorrect");
    }

    /*//////////////////////////////////////////////////////////////
                    APPROVAL HASH TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetApprovalHash_DifferentForDifferentParams() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params1 = _getDefaultParams();

        // Change owner field
        CowEvcOpenPositionWrapper.OpenPositionParams memory params2 = _getDefaultParams();
        params2.owner = ACCOUNT;

        // Change borrowAmount field
        CowEvcOpenPositionWrapper.OpenPositionParams memory params3 = _getDefaultParams();
        params3.borrowAmount = 600e18;

        bytes32 hash1 = CowEvcOpenPositionWrapper(address(wrapper)).getApprovalHash(params1);
        bytes32 hash2 = CowEvcOpenPositionWrapper(address(wrapper)).getApprovalHash(params2);
        bytes32 hash3 = CowEvcOpenPositionWrapper(address(wrapper)).getApprovalHash(params3);

        assertNotEq(hash1, hash2, "Hash should differ for different params");
        assertNotEq(hash1, hash3, "Hash should differ for different params");
    }

    /*//////////////////////////////////////////////////////////////
                    ENCODE PERMIT DATA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EncodePermitData_EncodesAsExpected() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();

        bytes memory permitData = CowEvcOpenPositionWrapper(address(wrapper)).encodePermitData(params);
        (IEVC.BatchItem[] memory items, bytes32 paramsHash) = _decodePermitData(permitData);

        assertEq(
            paramsHash, CowEvcOpenPositionWrapper(address(wrapper)).getApprovalHash(params), "Params hash should match"
        );

        assertEq(items[0].targetContract, address(mockEvc), "First item should target EVC");
        assertEq(
            items[0].data,
            abi.encodeCall(IEVC.enableCollateral, (ACCOUNT, COLLATERAL_VAULT)),
            "Should enable collateral"
        );

        assertEq(items[1].targetContract, address(mockEvc), "Second item should target EVC");
        assertEq(
            items[1].data, abi.encodeCall(IEVC.enableController, (ACCOUNT, BORROW_VAULT)), "Should enable controller"
        );

        assertEq(items[2].targetContract, COLLATERAL_VAULT, "Third item should target collateral vault");
        assertEq(items[2].onBehalfOfAccount, OWNER, "Should deposit on behalf of owner");
        assertEq(
            items[2].data,
            abi.encodeCall(IERC4626.deposit, (DEFAULT_COLLATERAL_AMOUNT, ACCOUNT)),
            "Should deposit collateral"
        );

        assertEq(items[3].targetContract, BORROW_VAULT, "Fourth item should target borrow vault");
        assertEq(items[3].onBehalfOfAccount, ACCOUNT, "Should borrow on behalf of account");
        assertEq(
            items[3].data, abi.encodeCall(IBorrowing.borrow, (DEFAULT_BORROW_AMOUNT, OWNER)), "Should borrow to owner"
        );

        assertEq(items.length, 4, "Should have exactly 4 batch items");
    }

    /*//////////////////////////////////////////////////////////////
                    WRAPPED SETTLE TESTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                    EDGE CASE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ZeroCollateralAmount() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();
        params.collateralAmount = 0; // Zero collateral

        bytes memory permitData = CowEvcOpenPositionWrapper(address(wrapper)).encodePermitData(params);
        (IEVC.BatchItem[] memory items,) = _decodePermitData(permitData);

        // Should still have deposit call, just with 0 amount
        assertEq(items[2].data, abi.encodeCall(IERC4626.deposit, (0, ACCOUNT)), "Should deposit 0");
    }

    function test_SameOwnerAndAccount() public view {
        CowEvcOpenPositionWrapper.OpenPositionParams memory params = _getDefaultParams();
        params.account = OWNER; // Same as owner

        bytes memory permitData = CowEvcOpenPositionWrapper(address(wrapper)).encodePermitData(params);
        (IEVC.BatchItem[] memory items,) = _decodePermitData(permitData);

        // Should still work, but with same address
        assertEq(items[2].onBehalfOfAccount, OWNER, "Deposit should be on behalf of owner");
        assertEq(items[3].onBehalfOfAccount, OWNER, "Borrow should be on behalf of account");
    }
}
