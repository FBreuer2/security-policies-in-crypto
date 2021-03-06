pragma solidity >=0.4.21;

library HelperLibrary {


    function getEncodedChallenge(bytes32 challenge) public pure returns (bytes memory) {
        bytes memory alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        // We can hardcode the returned value here because base64 has a deterministic encoding size
        bytes memory encodedString = new bytes(43);

        // The idea is that the challenge is shifted and only the last 6 bits are converted to a uint
        // The &-mask is in binary "000...011111"
        uint offsetEncodedByte = 0;
        uint shiftWidth = 32*8;
        // get the first 251 bits
        while (shiftWidth > 6) {
            shiftWidth -= 6;
            encodedString[offsetEncodedByte] = alphabet[uint((challenge >> shiftWidth) &
                                                        bytes32(hex'000000000000000000000000000000000000000000000000000000000000003F'))];
            offsetEncodedByte++;
        }

        // last 4 bits
        encodedString[offsetEncodedByte] = alphabet[uint((challenge << 2) &
                                                    bytes32(hex'000000000000000000000000000000000000000000000000000000000000003F'))];

        return encodedString;
    }

    function verifyCorrectChallenge(bytes memory clientData, bytes32 challenge) public pure returns (bool) {
        bytes memory prefix = "\"challenge\":\"";
        bytes memory encodedChallenge = getEncodedChallenge(challenge);

        uint lengthPattern = prefix.length + encodedChallenge.length + 1;
        bytes memory searchString = new bytes(lengthPattern);

        uint k = 0;
        uint i = 0;

        for (i = 0; i < prefix.length; i++) {
            searchString[k++] = prefix[i];
        }

        for (i = 0; i < encodedChallenge.length; i++) {
            searchString[k++] = encodedChallenge[i];
        }

        searchString[k] = "\"";

        uint lengthText = clientData.length;

        for (i = 0; i <= lengthText - lengthPattern; i++) {
            uint j;

            for (j = 0; j < lengthPattern; j++)
                if (clientData[i + j] != searchString[j])
                    break;

            if (j == lengthPattern) return true;
        }

        return false;
    }

}