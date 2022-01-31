package staking

import (
	"fmt"
	"math/big"

	"github.com/0xPolygon/polygon-edge/chain"
	"github.com/0xPolygon/polygon-edge/helper/hex"
	"github.com/0xPolygon/polygon-edge/helper/keccak"
	"github.com/0xPolygon/polygon-edge/types"
)

// PadLeftOrTrim left-pads the passed in byte array to the specified size,
// or trims the array if it exceeds the passed in size
func PadLeftOrTrim(bb []byte, size int) []byte {
	l := len(bb)
	if l == size {
		return bb
	}

	if l > size {
		return bb[l-size:]
	}

	tmp := make([]byte, size)
	copy(tmp[size-l:], bb)

	return tmp
}

// getAddressMapping returns the key for the SC storage mapping (address => something)
//
// More information:
// https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
func getAddressMapping(address types.Address, slot int64) []byte {
	bigSlot := big.NewInt(slot)

	finalSlice := append(
		PadLeftOrTrim(address.Bytes(), 32),
		PadLeftOrTrim(bigSlot.Bytes(), 32)...,
	)
	keccakValue := keccak.Keccak256(nil, finalSlice)

	return keccakValue
}

// getIndexWithOffset is a helper method for adding an offset to the already found keccak hash
func getIndexWithOffset(keccakHash []byte, offset int64) []byte {
	bigOffset := big.NewInt(offset)
	bigKeccak := big.NewInt(0).SetBytes(keccakHash)

	bigKeccak.Add(bigKeccak, bigOffset)

	return bigKeccak.Bytes()
}

// getStorageIndexes is a helper function for getting the correct indexes
// of the storage slots which need to be modified during bootstrap.
//
// It is SC dependant, and based on the SC located at:
// https://github.com/0xPolygon/staking-contracts/
func getStorageIndexes(address types.Address, index int64) *StorageIndexes {
	storageIndexes := StorageIndexes{}

	// Get the indexes for the mappings
	// The index for the mapping is retrieved with:
	// keccak(address . slot)
	// . stands for concatenation (basically appending the bytes)
	storageIndexes.AddressToIsValidatorIndex = getAddressMapping(address, addressToIsValidatorSlot)
	storageIndexes.AddressToStakedAmountIndex = getAddressMapping(address, addressToStakedAmountSlot)
	storageIndexes.AddressToValidatorIndexIndex = getAddressMapping(address, addressToValidatorIndexSlot)

	// Get the indexes for _validators, _stakedAmount
	// Index for regular types is calculated as just the regular slot
	storageIndexes.StakedAmountIndex = big.NewInt(stakedAmountSlot).Bytes()

	// Index for array types is calculated as keccak(slot) + index
	// The slot for the dynamic arrays that's put in the keccak needs to be in hex form (padded 64 chars)
	storageIndexes.ValidatorsIndex = getIndexWithOffset(
		keccak.Keccak256(nil, PadLeftOrTrim(big.NewInt(validatorsSlot).Bytes(), 32)),
		index,
	)

	// For any dynamic array in Solidity, the size of the actual array should be
	// located on slot x
	storageIndexes.ValidatorsArraySizeIndex = []byte{byte(validatorsSlot)}

	return &storageIndexes
}

// StorageIndexes is a wrapper for different storage indexes that
// need to be modified
type StorageIndexes struct {
	ValidatorsIndex              []byte // []address
	ValidatorsArraySizeIndex     []byte // []address size
	AddressToIsValidatorIndex    []byte // mapping(address => bool)
	AddressToStakedAmountIndex   []byte // mapping(address => uint256)
	AddressToValidatorIndexIndex []byte // mapping(address => uint256)
	StakedAmountIndex            []byte // uint256
}

// Slot definitions for SC storage
var (
	validatorsSlot              = int64(0) // Slot 0
	addressToIsValidatorSlot    = int64(1) // Slot 1
	addressToStakedAmountSlot   = int64(2) // Slot 2
	addressToValidatorIndexSlot = int64(3) // Slot 3
	stakedAmountSlot            = int64(4) // Slot 4
)

const (
	DefaultStakedBalance = "0x3635C9ADC5DEA00000" // 1000 ETH
	//nolint: lll
	StakingSCBytecode = "0x6080604052600436106100745760003560e01c806350d68ed81161004e57806350d68ed8146101335780636a7687051461015e578063ca1e781914610189578063f90ecacc146101b4576100e2565b80632def6620146100e7578063373d6132146100fe5780633a4b66f114610129576100e2565b366100e2576100983373ffffffffffffffffffffffffffffffffffffffff166101f1565b156100d8576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100cf90610d82565b60405180910390fd5b6100e0610204565b005b600080fd5b3480156100f357600080fd5b506100fc610480565b005b34801561010a57600080fd5b5061011361056b565b6040516101209190610dbd565b60405180910390f35b610131610575565b005b34801561013f57600080fd5b506101486105de565b6040516101559190610da2565b60405180910390f35b34801561016a57600080fd5b506101736105eb565b6040516101809190610dd8565b60405180910390f35b34801561019557600080fd5b5061019e6105f0565b6040516101ab9190610d00565b60405180910390f35b3480156101c057600080fd5b506101db60048036038101906101d69190610b6b565b61067e565b6040516101e89190610ce5565b60405180910390f35b600080823b905060008111915050919050565b34600460008282546102169190610e3d565b9250508190555034600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825461026c9190610e3d565b92505081905550600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff161580156103275750683635c9adc5dea000006fffffffffffffffffffffffffffffffff16600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410155b156104305760018060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff021916908315150217905550600080549050600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506000339080600181540180825580915050600190039060005260206000200160009091909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b3373ffffffffffffffffffffffffffffffffffffffff167f9e71bc8eea02a63969f509818f2dafb9254532904319f9dbda79b67bd34a5f3d346040516104769190610dbd565b60405180910390a2565b61049f3373ffffffffffffffffffffffffffffffffffffffff166101f1565b156104df576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104d690610d82565b60405180910390fd5b6000600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205411610561576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161055890610d42565b60405180910390fd5b6105696106bd565b565b6000600454905090565b6105943373ffffffffffffffffffffffffffffffffffffffff166101f1565b156105d4576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105cb90610d82565b60405180910390fd5b6105dc610204565b565b683635c9adc5dea0000081565b600481565b6060600080548060200260200160405190810160405280929190818152602001828054801561067457602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001906001019080831161062a575b5050505050905090565b6000818154811061068e57600080fd5b906000526020600020016000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600463ffffffff166000805490501161070b576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161070290610d22565b60405180910390fd5b6000600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16156107ab576107aa336108a1565b5b6000600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555080600460008282546108029190610e93565b925050819055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f1935050505015801561084f573d6000803e3d6000fd5b503373ffffffffffffffffffffffffffffffffffffffff167f0f5bb82176feb1b5e747e28471aa92156a04d9f3ab9f45f28e2d704232b93f75826040516108969190610dbd565b60405180910390a250565b600080549050600360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410610927576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161091e90610d62565b60405180910390fd5b6000600360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205490506000600160008054905061097f9190610e93565b9050808214610a6d57600080828154811061099d5761099c610f8d565b5b9060005260206000200160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905080600084815481106109df576109de610f8d565b5b9060005260206000200160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555082600360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550505b6000600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055506000600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055506000805480610b1c57610b1b610f5e565b5b6001900381819060005260206000200160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690559055505050565b600081359050610b65816110b1565b92915050565b600060208284031215610b8157610b80610fbc565b5b6000610b8f84828501610b56565b91505092915050565b6000610ba48383610bb0565b60208301905092915050565b610bb981610ec7565b82525050565b610bc881610ec7565b82525050565b6000610bd982610e03565b610be38185610e1b565b9350610bee83610df3565b8060005b83811015610c1f578151610c068882610b98565b9750610c1183610e0e565b925050600181019050610bf2565b5085935050505092915050565b6000610c39604483610e2c565b9150610c4482610fc1565b606082019050919050565b6000610c5c601d83610e2c565b9150610c6782611036565b602082019050919050565b6000610c7f601283610e2c565b9150610c8a8261105f565b602082019050919050565b6000610ca2601a83610e2c565b9150610cad82611088565b602082019050919050565b610cc181610ed9565b82525050565b610cd081610f15565b82525050565b610cdf81610f1f565b82525050565b6000602082019050610cfa6000830184610bbf565b92915050565b60006020820190508181036000830152610d1a8184610bce565b905092915050565b60006020820190508181036000830152610d3b81610c2c565b9050919050565b60006020820190508181036000830152610d5b81610c4f565b9050919050565b60006020820190508181036000830152610d7b81610c72565b9050919050565b60006020820190508181036000830152610d9b81610c95565b9050919050565b6000602082019050610db76000830184610cb8565b92915050565b6000602082019050610dd26000830184610cc7565b92915050565b6000602082019050610ded6000830184610cd6565b92915050565b6000819050602082019050919050565b600081519050919050565b6000602082019050919050565b600082825260208201905092915050565b600082825260208201905092915050565b6000610e4882610f15565b9150610e5383610f15565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610e8857610e87610f2f565b5b828201905092915050565b6000610e9e82610f15565b9150610ea983610f15565b925082821015610ebc57610ebb610f2f565b5b828203905092915050565b6000610ed282610ef5565b9050919050565b60006fffffffffffffffffffffffffffffffff82169050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b600063ffffffff82169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600080fd5b7f4e756d626572206f662076616c696461746f72732063616e2774206265206c6560008201527f7373207468616e204d696e696d756d52657175697265644e756d56616c69646160208201527f746f727300000000000000000000000000000000000000000000000000000000604082015250565b7f4f6e6c79207374616b65722063616e2063616c6c2066756e6374696f6e000000600082015250565b7f696e646578206f7574206f662072616e67650000000000000000000000000000600082015250565b7f4f6e6c7920454f412063616e2063616c6c2066756e6374696f6e000000000000600082015250565b6110ba81610f15565b81146110c557600080fd5b5056fea26469706673582212202afb344a0f43c7a1fa285424443e7da1246b7402227a7a9b93a1b089229568a364736f6c63430008070033"
)

// PredeployStakingSC is a helper method for setting up the staking smart contract account,
// using the passed in validators as prestaked validators
func PredeployStakingSC(
	validators []types.Address,
) (*chain.GenesisAccount, error) {
	// Set the code for the staking smart contract
	// Code retrieved from https://github.com/0xPolygon/staking-contracts
	scHex, _ := hex.DecodeHex(StakingSCBytecode)
	stakingAccount := &chain.GenesisAccount{
		Code: scHex,
	}

	// Parse the default staked balance value into *big.Int
	val := DefaultStakedBalance
	bigDefaultStakedBalance, err := types.ParseUint256orHex(&val)

	if err != nil {
		return nil, fmt.Errorf("unable to generate DefaultStatkedBalance, %w", err)
	}

	// Generate the empty account storage map
	storageMap := make(map[types.Hash]types.Hash)
	bigTrueValue := big.NewInt(1)
	stakedAmount := big.NewInt(0)

	for indx, validator := range validators {
		// Update the total staked amount
		stakedAmount.Add(stakedAmount, bigDefaultStakedBalance)

		// Get the storage indexes
		storageIndexes := getStorageIndexes(validator, int64(indx))

		// Set the value for the validators array
		storageMap[types.BytesToHash(storageIndexes.ValidatorsIndex)] =
			types.BytesToHash(
				validator.Bytes(),
			)

		// Set the value for the address -> validator array index mapping
		storageMap[types.BytesToHash(storageIndexes.AddressToIsValidatorIndex)] =
			types.BytesToHash(bigTrueValue.Bytes())

		// Set the value for the address -> staked amount mapping
		storageMap[types.BytesToHash(storageIndexes.AddressToStakedAmountIndex)] =
			types.StringToHash(hex.EncodeBig(bigDefaultStakedBalance))

		// Set the value for the address -> validator index mapping
		storageMap[types.BytesToHash(storageIndexes.AddressToValidatorIndexIndex)] =
			types.StringToHash(hex.EncodeUint64(uint64(indx)))

		// Set the value for the total staked amount
		storageMap[types.BytesToHash(storageIndexes.StakedAmountIndex)] =
			types.BytesToHash(stakedAmount.Bytes())

		// Set the value for the size of the validators array
		storageMap[types.BytesToHash(storageIndexes.ValidatorsArraySizeIndex)] =
			types.StringToHash(hex.EncodeUint64(uint64(indx + 1)))
	}

	// Save the storage map
	stakingAccount.Storage = storageMap

	// Set the Staking SC balance to numValidators * defaultStakedBalance
	stakingAccount.Balance = stakedAmount

	return stakingAccount, nil
}
