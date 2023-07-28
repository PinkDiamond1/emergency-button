// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package abi

import (
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// ISwapperABI is the input ABI used to generate the binding from.
const ISwapperABI = "[{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"},{\"internalType\":\"uint64\",\"name\":\"\",\"type\":\"uint64\"}],\"name\":\"assetInPool\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"asset1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"asset2\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"asset3\",\"type\":\"bytes\"},{\"internalType\":\"uint64\",\"name\":\"poolId\",\"type\":\"uint64\"}],\"name\":\"bind3Asset\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"fromAssetHash\",\"type\":\"bytes\"},{\"internalType\":\"uint64\",\"name\":\"poolId\",\"type\":\"uint64\"}],\"name\":\"bindAssetAndPool\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"pause\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"paused\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"\",\"type\":\"uint64\"}],\"name\":\"poolTokenMap\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"poolId\",\"type\":\"uint64\"},{\"internalType\":\"address\",\"name\":\"poolTokenAddress\",\"type\":\"address\"}],\"name\":\"registerPool\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"poolId\",\"type\":\"uint64\"},{\"internalType\":\"address\",\"name\":\"poolTokenAddress\",\"type\":\"address\"},{\"internalType\":\"bytes\",\"name\":\"asset1\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"asset2\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"asset3\",\"type\":\"bytes\"}],\"name\":\"registerPoolWith3Assets\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"unpause\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

// ISwapperFuncSigs maps the 4-byte function signature to its string representation.
var ISwapperFuncSigs = map[string]string{
	"84eae14e": "assetInPool(bytes,uint64)",
	"de77f69b": "bind3Asset(bytes,bytes,bytes,uint64)",
	"9462c985": "bindAssetAndPool(bytes,uint64)",
	"8456cb59": "pause()",
	"5c975abb": "paused()",
	"af249861": "poolTokenMap(uint64)",
	"a3e28eb4": "registerPool(uint64,address)",
	"16675e4f": "registerPoolWith3Assets(uint64,address,bytes,bytes,bytes)",
	"3f4ba83a": "unpause()",
}

// ISwapperBin is the compiled bytecode used for deploying new contracts.
var ISwapperBin = "0x608060405234801561001057600080fd5b506106b9806100206000396000f3fe608060405234801561001057600080fd5b50600436106100935760003560e01c806384eae14e1161006657806384eae14e1461028b5780639462c9851461033b578063a3e28eb4146103eb578063af24986114610421578063de77f69b1461046457610093565b806316675e4f146100985780633f4ba83a146102675780635c975abb1461026f5780638456cb5914610267575b600080fd5b610265600480360360a08110156100ae57600080fd5b67ffffffffffffffff823516916001600160a01b0360208201351691810190606081016040820135600160201b8111156100e757600080fd5b8201836020820111156100f957600080fd5b803590602001918460018302840111600160201b8311171561011a57600080fd5b91908080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509295949360208101935035915050600160201b81111561016c57600080fd5b82018360208201111561017e57600080fd5b803590602001918460018302840111600160201b8311171561019f57600080fd5b91908080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509295949360208101935035915050600160201b8111156101f157600080fd5b82018360208201111561020357600080fd5b803590602001918460018302840111600160201b8311171561022457600080fd5b91908080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092955061061e945050505050565b005b610265610625565b610277610627565b604080519115158252519081900360200190f35b610277600480360360408110156102a157600080fd5b810190602081018135600160201b8111156102bb57600080fd5b8201836020820111156102cd57600080fd5b803590602001918460018302840111600160201b831117156102ee57600080fd5b91908080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509295505050903567ffffffffffffffff16915061062c9050565b6102776004803603604081101561035157600080fd5b810190602081018135600160201b81111561036b57600080fd5b82018360208201111561037d57600080fd5b803590602001918460018302840111600160201b8311171561039e57600080fd5b91908080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509295505050903567ffffffffffffffff16915061065a9050565b6102776004803603604081101561040157600080fd5b50803567ffffffffffffffff1690602001356001600160a01b031661065a565b6104486004803603602081101561043757600080fd5b503567ffffffffffffffff16610662565b604080516001600160a01b039092168252519081900360200190f35b6102656004803603608081101561047a57600080fd5b810190602081018135600160201b81111561049457600080fd5b8201836020820111156104a657600080fd5b803590602001918460018302840111600160201b831117156104c757600080fd5b91908080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509295949360208101935035915050600160201b81111561051957600080fd5b82018360208201111561052b57600080fd5b803590602001918460018302840111600160201b8311171561054c57600080fd5b91908080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509295949360208101935035915050600160201b81111561059e57600080fd5b8201836020820111156105b057600080fd5b803590602001918460018302840111600160201b831117156105d157600080fd5b91908080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509295505050903567ffffffffffffffff16915061067d9050565b5050505050565b565b600090565b8151602081840181018051600080835293830195830195909520949052929092528152604090205460ff1681565b600092915050565b6001602052600090815260409020546001600160a01b031681565b5050505056fea2646970667358221220ca57344cfce865e7b80ba3a54c3048d833be830fcaa58b9ef71883b08ab2575d64736f6c634300060c0033"

// DeployISwapper deploys a new Ethereum contract, binding an instance of ISwapper to it.
func DeployISwapper(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *ISwapper, error) {
	parsed, err := abi.JSON(strings.NewReader(ISwapperABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(ISwapperBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ISwapper{ISwapperCaller: ISwapperCaller{contract: contract}, ISwapperTransactor: ISwapperTransactor{contract: contract}, ISwapperFilterer: ISwapperFilterer{contract: contract}}, nil
}

// ISwapper is an auto generated Go binding around an Ethereum contract.
type ISwapper struct {
	ISwapperCaller     // Read-only binding to the contract
	ISwapperTransactor // Write-only binding to the contract
	ISwapperFilterer   // Log filterer for contract events
}

// ISwapperCaller is an auto generated read-only Go binding around an Ethereum contract.
type ISwapperCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ISwapperTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ISwapperTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ISwapperFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ISwapperFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ISwapperSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ISwapperSession struct {
	Contract     *ISwapper         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ISwapperCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ISwapperCallerSession struct {
	Contract *ISwapperCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// ISwapperTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ISwapperTransactorSession struct {
	Contract     *ISwapperTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// ISwapperRaw is an auto generated low-level Go binding around an Ethereum contract.
type ISwapperRaw struct {
	Contract *ISwapper // Generic contract binding to access the raw methods on
}

// ISwapperCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ISwapperCallerRaw struct {
	Contract *ISwapperCaller // Generic read-only contract binding to access the raw methods on
}

// ISwapperTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ISwapperTransactorRaw struct {
	Contract *ISwapperTransactor // Generic write-only contract binding to access the raw methods on
}

// NewISwapper creates a new instance of ISwapper, bound to a specific deployed contract.
func NewISwapper(address common.Address, backend bind.ContractBackend) (*ISwapper, error) {
	contract, err := bindISwapper(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ISwapper{ISwapperCaller: ISwapperCaller{contract: contract}, ISwapperTransactor: ISwapperTransactor{contract: contract}, ISwapperFilterer: ISwapperFilterer{contract: contract}}, nil
}

// NewISwapperCaller creates a new read-only instance of ISwapper, bound to a specific deployed contract.
func NewISwapperCaller(address common.Address, caller bind.ContractCaller) (*ISwapperCaller, error) {
	contract, err := bindISwapper(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ISwapperCaller{contract: contract}, nil
}

// NewISwapperTransactor creates a new write-only instance of ISwapper, bound to a specific deployed contract.
func NewISwapperTransactor(address common.Address, transactor bind.ContractTransactor) (*ISwapperTransactor, error) {
	contract, err := bindISwapper(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ISwapperTransactor{contract: contract}, nil
}

// NewISwapperFilterer creates a new log filterer instance of ISwapper, bound to a specific deployed contract.
func NewISwapperFilterer(address common.Address, filterer bind.ContractFilterer) (*ISwapperFilterer, error) {
	contract, err := bindISwapper(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ISwapperFilterer{contract: contract}, nil
}

// bindISwapper binds a generic wrapper to an already deployed contract.
func bindISwapper(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ISwapperABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ISwapper *ISwapperRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ISwapper.Contract.ISwapperCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ISwapper *ISwapperRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ISwapper.Contract.ISwapperTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ISwapper *ISwapperRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ISwapper.Contract.ISwapperTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ISwapper *ISwapperCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ISwapper.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ISwapper *ISwapperTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ISwapper.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ISwapper *ISwapperTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ISwapper.Contract.contract.Transact(opts, method, params...)
}

// AssetInPool is a free data retrieval call binding the contract method 0x84eae14e.
//
// Solidity: function assetInPool(bytes , uint64 ) view returns(bool)
func (_ISwapper *ISwapperCaller) AssetInPool(opts *bind.CallOpts, arg0 []byte, arg1 uint64) (bool, error) {
	var out []interface{}
	err := _ISwapper.contract.Call(opts, &out, "assetInPool", arg0, arg1)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// AssetInPool is a free data retrieval call binding the contract method 0x84eae14e.
//
// Solidity: function assetInPool(bytes , uint64 ) view returns(bool)
func (_ISwapper *ISwapperSession) AssetInPool(arg0 []byte, arg1 uint64) (bool, error) {
	return _ISwapper.Contract.AssetInPool(&_ISwapper.CallOpts, arg0, arg1)
}

// AssetInPool is a free data retrieval call binding the contract method 0x84eae14e.
//
// Solidity: function assetInPool(bytes , uint64 ) view returns(bool)
func (_ISwapper *ISwapperCallerSession) AssetInPool(arg0 []byte, arg1 uint64) (bool, error) {
	return _ISwapper.Contract.AssetInPool(&_ISwapper.CallOpts, arg0, arg1)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_ISwapper *ISwapperCaller) Paused(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _ISwapper.contract.Call(opts, &out, "paused")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_ISwapper *ISwapperSession) Paused() (bool, error) {
	return _ISwapper.Contract.Paused(&_ISwapper.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_ISwapper *ISwapperCallerSession) Paused() (bool, error) {
	return _ISwapper.Contract.Paused(&_ISwapper.CallOpts)
}

// PoolTokenMap is a free data retrieval call binding the contract method 0xaf249861.
//
// Solidity: function poolTokenMap(uint64 ) view returns(address)
func (_ISwapper *ISwapperCaller) PoolTokenMap(opts *bind.CallOpts, arg0 uint64) (common.Address, error) {
	var out []interface{}
	err := _ISwapper.contract.Call(opts, &out, "poolTokenMap", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// PoolTokenMap is a free data retrieval call binding the contract method 0xaf249861.
//
// Solidity: function poolTokenMap(uint64 ) view returns(address)
func (_ISwapper *ISwapperSession) PoolTokenMap(arg0 uint64) (common.Address, error) {
	return _ISwapper.Contract.PoolTokenMap(&_ISwapper.CallOpts, arg0)
}

// PoolTokenMap is a free data retrieval call binding the contract method 0xaf249861.
//
// Solidity: function poolTokenMap(uint64 ) view returns(address)
func (_ISwapper *ISwapperCallerSession) PoolTokenMap(arg0 uint64) (common.Address, error) {
	return _ISwapper.Contract.PoolTokenMap(&_ISwapper.CallOpts, arg0)
}

// Bind3Asset is a paid mutator transaction binding the contract method 0xde77f69b.
//
// Solidity: function bind3Asset(bytes asset1, bytes asset2, bytes asset3, uint64 poolId) returns()
func (_ISwapper *ISwapperTransactor) Bind3Asset(opts *bind.TransactOpts, asset1 []byte, asset2 []byte, asset3 []byte, poolId uint64) (*types.Transaction, error) {
	return _ISwapper.contract.Transact(opts, "bind3Asset", asset1, asset2, asset3, poolId)
}

// Bind3Asset is a paid mutator transaction binding the contract method 0xde77f69b.
//
// Solidity: function bind3Asset(bytes asset1, bytes asset2, bytes asset3, uint64 poolId) returns()
func (_ISwapper *ISwapperSession) Bind3Asset(asset1 []byte, asset2 []byte, asset3 []byte, poolId uint64) (*types.Transaction, error) {
	return _ISwapper.Contract.Bind3Asset(&_ISwapper.TransactOpts, asset1, asset2, asset3, poolId)
}

// Bind3Asset is a paid mutator transaction binding the contract method 0xde77f69b.
//
// Solidity: function bind3Asset(bytes asset1, bytes asset2, bytes asset3, uint64 poolId) returns()
func (_ISwapper *ISwapperTransactorSession) Bind3Asset(asset1 []byte, asset2 []byte, asset3 []byte, poolId uint64) (*types.Transaction, error) {
	return _ISwapper.Contract.Bind3Asset(&_ISwapper.TransactOpts, asset1, asset2, asset3, poolId)
}

// BindAssetAndPool is a paid mutator transaction binding the contract method 0x9462c985.
//
// Solidity: function bindAssetAndPool(bytes fromAssetHash, uint64 poolId) returns(bool)
func (_ISwapper *ISwapperTransactor) BindAssetAndPool(opts *bind.TransactOpts, fromAssetHash []byte, poolId uint64) (*types.Transaction, error) {
	return _ISwapper.contract.Transact(opts, "bindAssetAndPool", fromAssetHash, poolId)
}

// BindAssetAndPool is a paid mutator transaction binding the contract method 0x9462c985.
//
// Solidity: function bindAssetAndPool(bytes fromAssetHash, uint64 poolId) returns(bool)
func (_ISwapper *ISwapperSession) BindAssetAndPool(fromAssetHash []byte, poolId uint64) (*types.Transaction, error) {
	return _ISwapper.Contract.BindAssetAndPool(&_ISwapper.TransactOpts, fromAssetHash, poolId)
}

// BindAssetAndPool is a paid mutator transaction binding the contract method 0x9462c985.
//
// Solidity: function bindAssetAndPool(bytes fromAssetHash, uint64 poolId) returns(bool)
func (_ISwapper *ISwapperTransactorSession) BindAssetAndPool(fromAssetHash []byte, poolId uint64) (*types.Transaction, error) {
	return _ISwapper.Contract.BindAssetAndPool(&_ISwapper.TransactOpts, fromAssetHash, poolId)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_ISwapper *ISwapperTransactor) Pause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ISwapper.contract.Transact(opts, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_ISwapper *ISwapperSession) Pause() (*types.Transaction, error) {
	return _ISwapper.Contract.Pause(&_ISwapper.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_ISwapper *ISwapperTransactorSession) Pause() (*types.Transaction, error) {
	return _ISwapper.Contract.Pause(&_ISwapper.TransactOpts)
}

// RegisterPool is a paid mutator transaction binding the contract method 0xa3e28eb4.
//
// Solidity: function registerPool(uint64 poolId, address poolTokenAddress) returns(bool)
func (_ISwapper *ISwapperTransactor) RegisterPool(opts *bind.TransactOpts, poolId uint64, poolTokenAddress common.Address) (*types.Transaction, error) {
	return _ISwapper.contract.Transact(opts, "registerPool", poolId, poolTokenAddress)
}

// RegisterPool is a paid mutator transaction binding the contract method 0xa3e28eb4.
//
// Solidity: function registerPool(uint64 poolId, address poolTokenAddress) returns(bool)
func (_ISwapper *ISwapperSession) RegisterPool(poolId uint64, poolTokenAddress common.Address) (*types.Transaction, error) {
	return _ISwapper.Contract.RegisterPool(&_ISwapper.TransactOpts, poolId, poolTokenAddress)
}

// RegisterPool is a paid mutator transaction binding the contract method 0xa3e28eb4.
//
// Solidity: function registerPool(uint64 poolId, address poolTokenAddress) returns(bool)
func (_ISwapper *ISwapperTransactorSession) RegisterPool(poolId uint64, poolTokenAddress common.Address) (*types.Transaction, error) {
	return _ISwapper.Contract.RegisterPool(&_ISwapper.TransactOpts, poolId, poolTokenAddress)
}

// RegisterPoolWith3Assets is a paid mutator transaction binding the contract method 0x16675e4f.
//
// Solidity: function registerPoolWith3Assets(uint64 poolId, address poolTokenAddress, bytes asset1, bytes asset2, bytes asset3) returns()
func (_ISwapper *ISwapperTransactor) RegisterPoolWith3Assets(opts *bind.TransactOpts, poolId uint64, poolTokenAddress common.Address, asset1 []byte, asset2 []byte, asset3 []byte) (*types.Transaction, error) {
	return _ISwapper.contract.Transact(opts, "registerPoolWith3Assets", poolId, poolTokenAddress, asset1, asset2, asset3)
}

// RegisterPoolWith3Assets is a paid mutator transaction binding the contract method 0x16675e4f.
//
// Solidity: function registerPoolWith3Assets(uint64 poolId, address poolTokenAddress, bytes asset1, bytes asset2, bytes asset3) returns()
func (_ISwapper *ISwapperSession) RegisterPoolWith3Assets(poolId uint64, poolTokenAddress common.Address, asset1 []byte, asset2 []byte, asset3 []byte) (*types.Transaction, error) {
	return _ISwapper.Contract.RegisterPoolWith3Assets(&_ISwapper.TransactOpts, poolId, poolTokenAddress, asset1, asset2, asset3)
}

// RegisterPoolWith3Assets is a paid mutator transaction binding the contract method 0x16675e4f.
//
// Solidity: function registerPoolWith3Assets(uint64 poolId, address poolTokenAddress, bytes asset1, bytes asset2, bytes asset3) returns()
func (_ISwapper *ISwapperTransactorSession) RegisterPoolWith3Assets(poolId uint64, poolTokenAddress common.Address, asset1 []byte, asset2 []byte, asset3 []byte) (*types.Transaction, error) {
	return _ISwapper.Contract.RegisterPoolWith3Assets(&_ISwapper.TransactOpts, poolId, poolTokenAddress, asset1, asset2, asset3)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_ISwapper *ISwapperTransactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ISwapper.contract.Transact(opts, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_ISwapper *ISwapperSession) Unpause() (*types.Transaction, error) {
	return _ISwapper.Contract.Unpause(&_ISwapper.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_ISwapper *ISwapperTransactorSession) Unpause() (*types.Transaction, error) {
	return _ISwapper.Contract.Unpause(&_ISwapper.TransactOpts)
}

