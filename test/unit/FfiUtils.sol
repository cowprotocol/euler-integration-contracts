// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8;

import {Vm} from "forge-std/Vm.sol";

library FfiUtils {
    /// @dev Attempts an FFI call and skips the test if FFI is disabled. Reverts on any other error.
    function ffiOrSkip(Vm vm, string[] memory inputs) internal returns (bytes memory) {
        /// forge-lint: disable-next-line(unsafe-cheatcode)
        try vm.ffi(inputs) returns (bytes memory result) {
            return result;
        } catch (bytes memory err) {
            // We only want to silently ignore this if its because FFI is disabled
            vm.skip(
                keccak256(
                    abi.encodeWithSignature(
                        "CheatcodeError(string)",
                        "vm.ffi: FFI is disabled; add the `--ffi` flag to allow tests to call external commands"
                    )
                ) == keccak256(err)
            );

            assembly {
                // bubble up error. length is at the beginning of the pointer, and the
                // revert contents 32 bytes after.
                revert(add(err, 32), mload(err))
            }
        }
    }
}
