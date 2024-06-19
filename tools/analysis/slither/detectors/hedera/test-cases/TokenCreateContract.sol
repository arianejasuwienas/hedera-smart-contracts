// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;
pragma experimental ABIEncoderV2;

import "./hedera-token-service/HederaTokenService.sol";
import "./hedera-token-service/ExpiryHelper.sol";
import "./hedera-token-service/KeyHelper.sol";

contract TokenCreateContract is HederaTokenService, ExpiryHelper, KeyHelper {
    function createFungibleTokenWithSECP256K1AdminKeyPublic(address treasury, bytes memory adminKey) public payable {
        IHederaTokenService.TokenKey[] memory keys = new IHederaTokenService.TokenKey[](5);
        keys[0] = getSingleKey(KeyType.ADMIN, KeyType.PAUSE, KeyValueType.SECP256K1, adminKey);
        IHederaTokenService.Expiry memory expiry = IHederaTokenService.Expiry(0, treasury, 8000000);
        IHederaTokenService.HederaToken memory token = IHederaTokenService.HederaToken(
            "tokenName", "tokenSymbol", treasury, "memo", true, 10000, false, keys, expiry
        );
        HederaTokenService.createFungibleToken(token, 10000, 8);
    }
}
