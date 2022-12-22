// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';

import './interfaces/IVerifier.sol';

contract Verifier is IVerifier {
  address[] signers;

  bytes32 public immutable DOMAIN_SEPARATOR;
  // keccak256('SetSigners(arress[] newSigners,uint256 deadline)')
  bytes32 public constant SET_SIGNERS_TYPEHASH = 0xac6c9b890961abf1aef102f796cddeb6d1dc83a8e0db329d17a4f54fbbdc4ef1;

  constructor() {
    DOMAIN_SEPARATOR = keccak256(
      abi.encode(
        keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
        keccak256('Bridge'),
        keccak256('1'),
        block.chainid,
        address(this)
      )
    );
  }

  function verify(
    bytes32 domainSeparator,
    bytes32 structHash,
    bytes[] calldata signatures
  ) public view returns (bool) {
    require(
      signers.length > 0 && signatures.length == signers.length,
      'Verifier: no signers or signatures length mismatch'
    );

    bytes32 digest = ECDSA.toTypedDataHash(domainSeparator, structHash);
    for (uint256 i; i < signers.length; i++) {
      address rec = ECDSA.recover(digest, signatures[i]);
      if (rec != signers[i]) {
        return false;
      }
    }

    return true;
  }

  function setSigners(
    address[] memory newSigners,
    uint256 deadline,
    bytes[] calldata signatures
  ) external {
    require(block.timestamp <= deadline, 'Verifier: expired');
    require(newSigners.length > 1, 'Verifier: must have at least two signers');
    if (signers.length > 0) {
      bytes32 structHash = keccak256(
        abi.encode(SET_SIGNERS_TYPEHASH, keccak256(abi.encodePacked(newSigners)), deadline)
      );
      require(verify(DOMAIN_SEPARATOR, structHash, signatures), 'Verifier: invalid signatures');
    }
    address prev = address(0);
    for (uint256 i; i < newSigners.length; i++) {
      require(newSigners[i] > prev, 'signers not sorted or has non unique or zero addresses');
      prev = newSigners[i];
    }
    signers = newSigners;
  }

  function getSigners() external view returns (address[] memory) {
    return signers;
  }
}
