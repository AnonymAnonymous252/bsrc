// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import '@openzeppelin/contracts/utils/Address.sol';
import '@openzeppelin/contracts/utils/Multicall.sol';

import './interfaces/IVerifier.sol';
import './libraries/SafeToken.sol';

contract Debiter is Multicall {
  using Address for address;
  using SafeToken for address;

  bytes32 public immutable DOMAIN_SEPARATOR;
  // keccak256('Debit(address account,address token,address target,uint256 amount,uint256 deadline)')
  bytes32 public constant DEBIT_TYPEHASH = 0xfa44b80a182b2c41481b62108bfc2211ce2540417177649352741e5d771536ea;
  // keccak256('SetVerifier(address newVerifier,uint256 deadline)')
  bytes32 public constant SET_VERIFIER_TYPEHASH = 0x83ff2829503e6b25933e0c1d0422aeb9b68fe6259418bffd98b105c4ef89c4d4;

  IVerifier public verifier;

  event Debited(address indexed account, address indexed token, address indexed target, uint256 amount);

  constructor() {
    DOMAIN_SEPARATOR = keccak256(
      abi.encode(
        keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
        keccak256('Debiter'),
        keccak256('1'),
        block.chainid,
        address(this)
      )
    );
  }

  function debit(
    address account,
    address token,
    address target,
    uint256 amount,
    uint256 deadline,
    bytes[] calldata signatures
  ) external {
    require(block.timestamp <= deadline, 'Debiter: expired');

    bytes32 structHash = keccak256(abi.encode(DEBIT_TYPEHASH, account, token, target, amount, deadline));
    require(verifier.verify(DOMAIN_SEPARATOR, structHash, signatures), 'Debiter: invalid signatures');

    token.move(account, target, amount);
    emit Debited(account, token, target, amount);
  }

  function setVerifier(
    IVerifier newVerifier,
    uint256 deadline,
    bytes[] calldata newSigs,
    bytes[] calldata oldSigs
  ) external {
    require(block.timestamp <= deadline, 'Debiter: expired');

    bytes32 structHash = keccak256(abi.encode(SET_VERIFIER_TYPEHASH, newVerifier, deadline));
    require(newVerifier.verify(DOMAIN_SEPARATOR, structHash, newSigs), 'Debiter: invalid signature for new verifier');

    if (address(verifier) != address(0)) {
      require(verifier.verify(DOMAIN_SEPARATOR, structHash, oldSigs), 'Debiter: invalid signature for old verifier');
    }

    verifier = newVerifier;
  }
}
