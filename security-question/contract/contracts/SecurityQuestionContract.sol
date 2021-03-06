pragma solidity ^0.6.1;


contract SecurityQuestionContract {
    /*
     * Structures and methods FQ
     */

    uint constant curveOrder = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Modified from https://github.com/androlo/standard-contracts/blob/master/contracts/src/crypto/ECCMath.sol
    function inverseMod(uint u) public pure returns (uint inversed) {
        uint tmp = u;

        if (tmp > curveOrder)
            tmp = u % curveOrder;

        int t1;
        int t2 = 1;
        uint r1 = curveOrder;
        uint r2 = tmp;
        uint q;

        while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int(q) * t2, r2, r1 - q * r2);
        }

        if (t1 < 0)
            return (curveOrder - uint(-t1));

        return uint(t1);
    }

    // calculates the lagrange for x and x_j = {others}
    function getLagrange(uint x, uint[] memory others) private pure returns (uint exponent) {
        uint product = 1;
        for (uint i = 0; i < others.length; i++) {
            if (others[i] != x) {
                uint upperTerm = -others[i] + curveOrder;
                uint lowerTerm = inverseMod((x + curveOrder - others[i]) % curveOrder);
                product = mulmod(product, mulmod(upperTerm, lowerTerm, curveOrder), curveOrder);
            }
        }

        return product;
    }

    /*
     * Structures and methods in G_1 and G2
     */ 
    struct G1Element{
        uint x;
        uint y;
    }


    uint constant fieldModulus = 21888242871839275222246405745257275088696311157297823662689037894645226208583;


    function getG1() internal pure returns(G1Element memory generator) {
        generator.x = 1;
        generator.y = 2;
        return generator;
    }

    function addInG1(G1Element memory e1, uint[2] memory e2) internal returns (G1Element memory sumElement) {
        uint[4] memory input;
        input[0] = e1.x;
        input[1] = e1.y;
        input[2] = e2[0];
        input[3] = e2[1];

        uint[2] memory output;

        assembly {
            if iszero(staticcall(gas(), 0x06, input, 0x80, output, 0x40)) {
                revert(0,0)
            }
        }
        sumElement.x = output[0];
        sumElement.y = output[1];
        return sumElement;
    }

    function multiply(G1Element memory element, uint scalar) internal returns (G1Element memory productElement) {
        uint[3] memory input;
        input[0] = element.x;
        input[1] = element.y;
        input[2] = scalar;

        uint[2] memory out;
        bool success;

        assembly {
            success := call(sub(gas(), 2000), 7, 0, input, 0x80, out, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        productElement.x = out[0];
        productElement.y = out[1];
        return productElement;
    }

    function equals(G1Element memory element1, G1Element memory element2) internal pure returns (bool) {
        return element1.x == element2.x && element1.y == element2.y;
    }

    function negate(G1Element memory p) internal pure returns (G1Element memory res) {
        res.x = p.x;
        res.y = (-p.y + fieldModulus) % fieldModulus ;
        return res;
    }


    function isEmpty(G1Element memory p) internal pure returns (bool) {
        return p.x == 0 && p.y == 0;
    }

    struct G2Element{
        uint[2] coeffs_x;
        uint[2] coeffs_y;
    }

    function isEmpty(G2Element memory p) internal pure returns (bool) {
        return p.coeffs_x[0] == 0 && p.coeffs_x[1] == 0 && p.coeffs_y[0] == 0 && p.coeffs_y[1] == 0;
    }


    /*
     * Checks the pairing. Please note that in the paper we use \prod{i} e((c_0_i)^lambda, k_i) = e(c_1_tilde, k), however we can't use that here.
     * Ethereum has a different pairing format, see https://github.com/ethereum/EIPs/blob/master/EIPS/eip-197.md
     * So we have to check if \prod{i} e((c_0_i)^lambda, k_i) * e(-c_1_tilde, k) = 1
     */
    function pairing(G1Element[] memory g1Elements, G2Element[] memory g2Elements) internal returns (bool) {
        require(g1Elements.length == g2Elements.length, "Points array length not matching");

        uint elements = g1Elements.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);

        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = g1Elements[i].x;
            input[i * 6 + 1] = g1Elements[i].y;
            input[i * 6 + 2] = g2Elements[i].coeffs_x[0];
            input[i * 6 + 3] = g2Elements[i].coeffs_x[1];
            input[i * 6 + 4] = g2Elements[i].coeffs_y[0];
            input[i * 6 + 5] = g2Elements[i].coeffs_y[1];
        }

        uint[1] memory out;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := call(sub(gas(), 2000), 8, 0, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }

        require(success, "Call to precompiled contract failed");
        return out[0] != 0;
    }

    /*
     * Structures for group management
     */ 
    mapping (address => Group) groups;

    struct Group {
        address owner;
        uint threshold;
        G1Element c_0;
        G1Element c_1;
        G1Element d_0;
        G1Element d_1;
        Party[] parties;
        bool isInitialized;
        mapping(bytes => Attempt) attempts;
        mapping(address => uint) xMapping;
    }

    struct Attempt {
        bytes id;
        Part[] parts;
        uint[] participatingMembers;
        G1Element c_0_tilde;
        G1Element c_1_tilde;
        G2Element k;
        bool verified;
        bool isNotEmpty;
    }

    struct Part {
        G1Element c_0_i;
        G2Element k_i;
        bool isVerified;
        uint x;
        uint exponent;
    }

    struct Party{
        address party;
        G1Element publicKey;
    }

    event Broadcast(address group, address sender, bytes message);

    event NewGroup(address group, address[] members, uint[2] c_0, uint[2] c_1, uint[2] d_0, uint[2] d_1);
    event NewQuery(address group, bytes id, uint[2][] c0, uint[2][] c1);
    event NewQueryNIZKPsP1(address group, bytes id, uint[2][] a1, uint[2][] b1, uint[2][] a2, uint[2][] b2);
    event NewQueryNIZKPsP2(address group, bytes id, uint[] d_1, uint[] d_2, uint[] r_1, uint[] r_2);
    event VerifiableAttempt(address group, bytes id);
    event VerificationResult(address group, bytes id, bool success);

    function createCommittee(address[] memory members, uint threshold, uint[2] memory c_0, uint[2] memory c_1, uint[2] memory d_0, uint[2] memory d_1) public payable {
        require(!groups[msg.sender].isInitialized, "Group already exists!");
        groups[msg.sender].owner = msg.sender;

        uint i;

        for (i = 0; i<members.length; i++) {
            Party memory newParty;
            newParty.party = members[i];

            groups[msg.sender].parties.push(newParty);
        }

        for (i = 0; i < members.length; i++) {
            groups[msg.sender].xMapping[members[i]] = i+1;
        }

        groups[msg.sender].threshold = threshold;
        groups[msg.sender].isInitialized = true;

        groups[msg.sender].c_0.x  = c_0[0];
        groups[msg.sender].c_0.y  = c_0[1];

        groups[msg.sender].c_1.x = c_1[0];
        groups[msg.sender].c_1.y = c_1[1];

        groups[msg.sender].d_0.x  = d_0[0];
        groups[msg.sender].d_0.y  = d_0[1];

        groups[msg.sender].d_1.x = d_1[0];
        groups[msg.sender].d_1.y = d_1[1];

        emit NewGroup(msg.sender, members, c_0, c_1, d_0, d_1);
    }

    // can only be done by the member itself
    function addKeyForMember(address group, uint[2] memory coeffs) public payable returns (bool) {
        require(groups[group].isInitialized, "This group doesn't exist!");

        for (uint i = 0; i<groups[group].parties.length; i++) {
            // find party
            if (groups[group].parties[i].party == msg.sender) {
                // check if key is already there
                require(isEmpty(groups[group].parties[i].publicKey) == true, "A key already exists");
                // add key
                G1Element memory newPublicKey;
                newPublicKey.x = coeffs[0];
                newPublicKey.y = coeffs[1];
                groups[group].parties[i].publicKey = newPublicKey;
                return true;
            }
        }

        return false;
    }

    function query(bytes memory id, uint[2][] memory c0, uint[2][] memory c1, uint[2] memory c_0_tilde, uint[2] memory c_1_tilde, uint[2][2] memory k) public payable {
        require(groups[msg.sender].isInitialized, "This group doesn't exist!");
        require(groups[msg.sender].attempts[id].isNotEmpty == false, "An attempt with this id already exist!");

        groups[msg.sender].attempts[id].id = id;

        groups[msg.sender].attempts[id].isNotEmpty = true;

        groups[msg.sender].attempts[id].c_0_tilde.x = c_0_tilde[0];
        groups[msg.sender].attempts[id].c_0_tilde.y = c_0_tilde[1];

        groups[msg.sender].attempts[id].c_1_tilde.x = c_1_tilde[0];
        groups[msg.sender].attempts[id].c_1_tilde.y = c_1_tilde[1];

        groups[msg.sender].attempts[id].k.coeffs_x = k[0];
        groups[msg.sender].attempts[id].k.coeffs_y = k[1];

        emit NewQuery(msg.sender, id, c0, c1);
    }

    function getChallengeForNZIK1(address group, bytes memory id, uint[2] memory a1, uint[2] memory b1, uint[2] memory a2, uint[2] memory b2) public view returns (uint) {
        bytes32 challengeNZIK1 = sha256(abi.encodePacked(group, id, a1[0], a1[1], a2[0], a2[1], b1[0], b1[1], b2[0], b2[1]));
        return uint(challengeNZIK1) % curveOrder;
    }

    function broadcastNIZKP1(address group, bytes memory id, uint[2][] memory a1, uint[2][] memory b1, uint[2][] memory a2, uint[2][] memory b2) public payable {
        emit NewQueryNIZKPsP1(group, id, a1, b1, a2, b2);
    }

    function broadcastNIZKP2(address group, bytes memory id, uint[] memory d_1, uint[] memory d_2, uint[] memory r_1, uint[] memory r_2) public payable {
        emit NewQueryNIZKPsP2(group, id, d_1, d_2, r_1, r_2);
    }

    function getKScalar(address group, bytes memory id) public view returns (uint scalar) {
        bytes32 kScalar = sha256(abi.encodePacked(group, id, groups[group].attempts[id].c_1_tilde.x, groups[group].attempts[id].c_1_tilde.y));
        return uint(kScalar) % curveOrder;

    }

    function addPart(address group, bytes memory id, 
                    uint[2] memory c_0_i, uint[2][2] memory k_i)  public payable {
        require(groups[group].isInitialized, "This group doesn't exist!");
        require(groups[group].attempts[id].isNotEmpty == true, "An attempt with this id doesn't exist!");

        uint xMember = groups[group].xMapping[msg.sender];
        require(xMember != 0, "This group doesn't have you as member!");

        for (uint i = 0; i < groups[group].attempts[id].parts.length; i++) {
            require(groups[group].attempts[id].parts[i].x != xMember, "Already added part!");
        }

        Part memory newPart;
        newPart.x = xMember;
        G1Element memory c_0_i_s;
        c_0_i_s.x = c_0_i[0];
        c_0_i_s.y = c_0_i[1];
        newPart.c_0_i = c_0_i_s;

        G2Element memory k_i_s;
        k_i_s.coeffs_x = k_i[0];
        k_i_s.coeffs_y = k_i[1];
        newPart.k_i = k_i_s;

        groups[group].attempts[id].parts.push(newPart);
        groups[group].attempts[id].participatingMembers.push(xMember);

        if (groups[group].attempts[id].participatingMembers.length == groups[group].threshold) {
            emit VerifiableAttempt(group, id);
        }
    }


    function getChallengeForNZIK2(address group, bytes memory id, uint[2] memory cR, uint[2] memory gR, uint xMember) public view returns (uint) {
        for (uint i = 0; i < groups[group].attempts[id].parts.length; i++) {
            if (groups[group].attempts[id].parts[i].x == xMember) {
                bytes32 challengeNZIK2 = sha256(abi.encodePacked(cR[0], cR[1], gR[0], gR[1], groups[group].attempts[id].c_0_tilde.x, groups[group].attempts[id].c_0_tilde.y));
                return uint(challengeNZIK2) % curveOrder;
            }
        }
    }


    function getPublicKeyForCurrentSender(address group) internal view returns (G1Element memory pKey) {
        for (uint i = 0; i<groups[group].parties.length; i++) {
            // find party
            if (groups[group].parties[i].party == msg.sender) {
                return groups[group].parties[i].publicKey;
            }
        }
    }

    function verifyNZIK2(address group, bytes memory id, uint[2] memory cR, uint[2] memory gR, uint z) public {
        require(groups[group].isInitialized, "This group doesn't exist!");
        require(groups[group].attempts[id].isNotEmpty == true, "An attempt with this id doesn't exist!");

        uint xMember = groups[group].xMapping[msg.sender];
        require(xMember != 0, "This group doesn't have you as member!");

        for (uint i = 0; i < groups[group].attempts[id].parts.length; i++) {
            if (groups[group].attempts[id].parts[i].x == xMember) {
                // check pairing
                G1Element[] memory pointsG1 = new G1Element[](3);

                uint challenge = getChallengeForNZIK2(group, id, cR, gR, xMember);

                pointsG1[0] = multiply(groups[group].attempts[id].parts[i].c_0_i, challenge);

                G1Element memory c_r;
                c_r.x = cR[0];
                c_r.y = cR[1];
                pointsG1[1] = c_r;

                pointsG1[2] = negate(multiply(groups[group].attempts[id].c_0_tilde, z));

                G2Element[] memory pointsG2 = new G2Element[](3);
                pointsG2[0] = groups[group].attempts[id].parts[i].k_i;
                pointsG2[1] = groups[group].attempts[id].k;
                pointsG2[2] = groups[group].attempts[id].k;

                require(pairing(pointsG1, pointsG2), "Validation of NZIK2 failed: Pairing");

                G1Element memory possibleGZ = addInG1(multiply(getPublicKeyForCurrentSender(group), challenge), gR);
                require(equals(possibleGZ, multiply(getG1(), z)), "Validation of NZIK2 failed: Pkey");
                
                return;
            }
        }
        return;
    }


    function verdict(bytes memory id) public payable {
        require(groups[msg.sender].attempts[id].participatingMembers.length >= groups[msg.sender].threshold,
                "This attempt doesn't have enough parts yet!");

        G1Element[] memory elementsG1 = new G1Element[](groups[msg.sender].attempts[id].parts.length + 1);
        G2Element[] memory elementsG2 = new G2Element[](groups[msg.sender].attempts[id].parts.length + 1);

        // calculate exponents
        for (uint i = 0; i<groups[msg.sender].attempts[id].parts.length; i++) {
            uint lagrangeExponent = getLagrange(groups[msg.sender].attempts[id].parts[i].x, groups[msg.sender].attempts[id].participatingMembers);
            elementsG1[i] = multiply(groups[msg.sender].attempts[id].parts[i].c_0_i, lagrangeExponent);

            elementsG2[i] = groups[msg.sender].attempts[id].parts[i].k_i;
        }

        elementsG1[groups[msg.sender].attempts[id].parts.length] = negate(groups[msg.sender].attempts[id].c_1_tilde);
        elementsG2[groups[msg.sender].attempts[id].parts.length] = groups[msg.sender].attempts[id].k;

        // calculation pairing
        require(pairing(elementsG1, elementsG2), "Incorrect answer");
        return;
    }

    function broadcast(address group, bytes memory message) public payable {
        emit Broadcast(group, msg.sender, message);
    }
}