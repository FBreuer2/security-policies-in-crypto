pragma solidity >=0.4.21;

import "./EllipticCurve.sol";
import "./ECRecovery.sol";

library ECC {

    // MessageHash is the hash of the message that should have been signed
    // Signature is the signature that was created over the hash of message
    // PublicKey is the uncompressed x,y representation of the key which should be used for verification
    function verifyECRecover(bytes32 messageHash, bytes publicKey, bytes signature) public pure returns (bool correctlySigned) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHash = keccak256(abi.encodePacked(prefix, messageHash));
        address signer = ECRecovery.recover(prefixedHash, signature);

        // get address from public key
        uint p1;
        uint p2;

        assembly {
            p1 := mload(add(publicKey, add(0x20, 1)))
            p2 := mload(add(publicKey, add(0x20, 33)))
        }
        address suppliedAddress = address(keccak256(abi.encodePacked(p1, p2)));

        return suppliedAddress == signer;
    }

    // MessageHash is the hash of the message that should have been signed
    // Signature is the signature that was created over the hash of message
    // PublicKey is the uncompressed x,y representation of the key which should be used for verification
    function verifySECP256R1(bytes32 messageHash, bytes publicKey, bytes signature) public pure returns (bool correctlySigned) {
        // get point coordinates from the public key, which has format compressionSign (1byte) + x (32 bytes) + y (32 bytes)
        uint x;
        uint y;

        assembly {
             x := mload(add(publicKey, add(0x20, 1)))
             y := mload(add(publicKey, add(0x20, 33)))
        }

        // signature format (ASN) is as follows:
        // | SEQUENCE (1 Byte)
        // | INTEGER (1 Byte) | LENGTH (1 Bytes) | <first point>
        // | INTEGER (1 Byte) | LENGTH (1 Bytes) | <second point>
        uint r;
        uint s;

        uint keyOffset = 4;

        // check if first point is padded
        if (signature[keyOffset] == 0) {
            keyOffset++;
        }

        assembly {
            r := mload(add(signature, add(0x20, keyOffset)))
        }

        keyOffset += 34;

        // check if second point is padded
        if (signature[keyOffset] == byte(0)) {
            keyOffset++;
        }

        assembly {
            s := mload(add(signature, add(0x20, keyOffset)))
        }

        return EllipticCurve.validateSignature(messageHash, [r, s], [x, y]);
    }

}
