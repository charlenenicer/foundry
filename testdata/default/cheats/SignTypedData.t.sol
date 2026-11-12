// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.18;

import "utils/Test.sol";

contract SignTypedDataTest is Test {
    string constant JSON_DATA = '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}]},"primaryType":"Person","domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},"message":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"}}';

    function testSignTypedDataWithPrivateKey() public {
        uint256 pk = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        (uint8 v, bytes32 r, bytes32 s) = vm.signTypedData(pk, JSON_DATA);

        bytes32 digest = vm.eip712HashTypedData(JSON_DATA);
        address expected = vm.addr(pk);
        address actual = ecrecover(digest, v, r, s);
        assertEq(actual, expected, "signer did not match");
    }

    function testSignTypedDataWithWallet() public {
        uint256 pk = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd;
        Vm.Wallet memory wallet = vm.createWallet(pk);
        (uint8 v, bytes32 r, bytes32 s) = vm.signTypedData(wallet, JSON_DATA);

        bytes32 digest = vm.eip712HashTypedData(JSON_DATA);
        address expected = wallet.addr;
        address actual = ecrecover(digest, v, r, s);
        assertEq(actual, expected, "signer did not match");
    }

    function testSignTypedDataMatchesManualDigest() public {
        uint256 pk = 0x1111111111111111111111111111111111111111111111111111111111111112;
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.signTypedData(pk, JSON_DATA);

        bytes32 digest = vm.eip712HashTypedData(JSON_DATA);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pk, digest);

        assertEq(v1, v2, "v should match");
        assertEq(r1, r2, "r should match");
        assertEq(s1, s2, "s should match");
    }

    function testSignTypedDataWithDifferentData() public {
        uint256 pk = 0x1111111111111111111111111111111111111111111111111111111111111111;

        string memory json1 = '{"types":{"EIP712Domain":[{"name":"name","type":"string"}],"Mail":[{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Test"},"message":{"contents":"Hello"}}';
        string memory json2 = '{"types":{"EIP712Domain":[{"name":"name","type":"string"}],"Mail":[{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Test"},"message":{"contents":"World"}}';

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.signTypedData(pk, json1);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.signTypedData(pk, json2);

        assertTrue(r1 != r2 || s1 != s2, "signatures should differ for different data");

        address expected = vm.addr(pk);
        assertEq(ecrecover(vm.eip712HashTypedData(json1), v1, r1, s1), expected, "first signature failed");
        assertEq(ecrecover(vm.eip712HashTypedData(json2), v2, r2, s2), expected, "second signature failed");
    }

    function testSignTypedDataInvalidJsonReverts() public {
        uint256 pk = 1;
        string memory invalidJson = "not valid json";

        try vm.signTypedData(pk, invalidJson) {
            fail();
        } catch {
            // Expected to revert
        }
    }
}
