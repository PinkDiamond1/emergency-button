pragma solidity ^0.6.0;


contract ILockProxy {
    mapping(address => mapping(uint64 => bytes)) public assetHashMap;
    mapping(uint64 => bytes) public proxyHashMap;
    function bindAssetHash(address fromAssetHash, uint64 toChainId, bytes memory toAssetHash) external returns (bool) {}
    function bindProxyHash(uint64 toChainId, bytes memory targetProxyHash) external returns (bool) {}
}