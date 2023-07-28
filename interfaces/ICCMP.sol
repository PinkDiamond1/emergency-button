pragma solidity ^0.6.0;


contract ICCMP {
    function owner() public view returns (address) {}
    function paused() public view returns (bool) {}
    function pauseEthCrossChainManager() external returns (bool) {}
    function unpauseEthCrossChainManager() external returns (bool) {}
}