// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EncryptDecrypt {
    
    /* 
    * @notice function to decrypt or encrypt data from key
    * @param data: encrypted or decrypted data bytes, key: key encryption algorithm bytes
    * @return decrypted or encrypted bytes
    */
    function encryptDecrypt(bytes memory data, bytes calldata key) public pure returns (bytes memory result) {
        
        // Store data length on stack for later use. 
        // ##########################################################################################
        // unsigned integer variable max 32 bytes length
        // ##########################################################################################
        uint256 length = data.length;


        // ##########################################################################################
        // code snippet to disable solidity code check for next code block
        // ##########################################################################################
        // solhint-disable-next-line no-inline-assembly

        // ##########################################################################################
        // inline assembly opening block
        // ##########################################################################################
        assembly {

            // Set result to free memory pointer.
            // ######################################################################################
            //  free empty bytes variable initialized at adress 0x40 in memory slot.
            // ######################################################################################
            result := mload(0x40)

            // Increase free memory pointer by length + 32. 
            // ######################################################################################
            // from memory slot address 0x40 is extended by an 
            // 32 bits length space + data length size
            // ######################################################################################
            mstore(0x40, add(add(result, length), 32))


            // Set result length. 
            // ######################################################################################
            // 32 bytes data length will be assigned at address 0x40  
            // previously assigned to result in memory slot
            // ######################################################################################
            mstore(result, length)
        }

    
        // Iterate over the data stepping by 32 bytes 
        // ##########################################################################################
        // native Solidity for loop
        // ##########################################################################################
        for (uint256 i = 0; i < length; i += 32) {

            // Generate hash of the key and offset 
            // ######################################################################################
            // native Solidity keccak256 32 bytes hash algorithm 
            // of concatenated bytes key with integer i
            // ######################################################################################
            bytes32 hash = keccak256(abi.encodePacked(key, i));
            
            // ######################################################################################
            // empty 32 bytes chunk initialized
            // ######################################################################################
            bytes32 chunk;

            // ######################################################################################
            // code snippet to disable solidity code check for next code block
            // ######################################################################################
            // solhint-disable-next-line no-inline-assembly


            // ######################################################################################
            // inline assembly opening block
            // ######################################################################################
            assembly {

                // Read 32-bytes data chunk
                // ##################################################################################
                // assign to memory slot chunk a 32 bytes extracted from byte step 32xi of data
                // ##################################################################################
                chunk := mload(add(data, add(i, 32)))

            }
            // XOR the chunk with hash
            // ######################################################################################
            // at binary level, xor can be explained as comparison "is not equal"
            // this will compare each binary 0 and 1, one by one between 32 bytes chunk and 
            // 32 bytes hash. The result will be assigned to chunk memory slot variable 
            // ######################################################################################
            chunk ^= hash;

            // ######################################################################################
            // code snippet to disable solidity code check for next code block
            // ######################################################################################
            // solhint-disable-next-line no-inline-assembly

            // ######################################################################################
            // inline assembly opening block
            // ######################################################################################
            assembly {

                // Write 32-byte encrypted chunk
                // ##################################################################################
                // add to bytes memory slot result a 32 bytes encrypted 
                // or decrypted chunk value at position start from 32xi step 
                // ##################################################################################
                mstore(add(result, add(i, 32)), chunk)
            }
        }

        // ##########################################################################################
        // the concatenated encrypted or decrypted result bytes will be returned
        // ##########################################################################################
    }
}