pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

contract ILockProxyWithLP {

    mapping(uint64 => bytes) public proxyHashMap;
    mapping(address => mapping(uint64 => bytes)) public assetHashMap;
    mapping(address => address) public assetLPMap;

    function pause() public returns (bool) {}
    function unpause() public returns (bool) {}
    function bindProxyHash(uint64 toChainId, bytes memory targetProxyHash) public returns (bool) {}
    function bindAssetHash(address fromAssetHash, uint64 toChainId, bytes memory toAssetHash) public returns (bool) {}
    function bindLPToAsset(address originAssetAddress, address LPTokenAddress) public returns (bool) {}
    function bindLPAndAsset(address fromAssetHash, address fromLPHash, uint64 toChainId, bytes memory toAssetHash, bytes memory toLPHash) public returns (bool) {}
    function bindProxyHashBatch(uint64[] memory toChainId, bytes[] memory targetProxyHash) public returns (bool) {}
    function bindAssetHashBatch(address[] memory fromAssetHash, uint64[] memory toChainId, bytes[] memory toAssetHash) public returns (bool) {}
    function bindLPToAssetBatch(address[] memory originAssetAddress, address[] memory LPTokenAddress) public returns (bool) {}
    function bindLPAndAssetBatch(address[] memory fromAssetHash, address[] memory fromLPHash, uint64[] memory toChainId, bytes[] memory toAssetHash, bytes[] memory toLPHash) public returns (bool) {} 
    function deposit(address originAssetAddress, uint amount) payable public returns (bool) {}
    function withdraw(address targetTokenAddress, uint amount) public returns (bool) {}
    function getBalanceFor(address fromAssetHash) public view returns (uint256) {}
}