// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

contract EcrecoverCaller {
    function callEcrecover(bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        address result = ecrecover(messageHash, v, r, s);
        return result;
    }
}
