// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package abi

import (
	"errors"
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
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// ICCMPMetaData contains all meta data concerning the ICCMP contract.
var ICCMPMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"pauseEthCrossChainManager\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"paused\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"unpauseEthCrossChainManager\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"8da5cb5b": "owner()",
		"3b9a80b8": "pauseEthCrossChainManager()",
		"5c975abb": "paused()",
		"4390c707": "unpauseEthCrossChainManager()",
	},
	Bin: "0x608060405234801561001057600080fd5b5060c28061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060465760003560e01c80633b9a80b814604b5780634390c70714604b5780635c975abb14604b5780638da5cb5b146065575b600080fd5b60516087565b604080519115158252519081900360200190f35b606b6087565b604080516001600160a01b039092168252519081900360200190f35b60009056fea264697066735822122066ba4f5ba17e1a32dd8db5dbd4965fbf41d9f4586400fb644949eb44a7c41a6d64736f6c634300060c0033",
}

// ICCMPABI is the input ABI used to generate the binding from.
// Deprecated: Use ICCMPMetaData.ABI instead.
var ICCMPABI = ICCMPMetaData.ABI

// Deprecated: Use ICCMPMetaData.Sigs instead.
// ICCMPFuncSigs maps the 4-byte function signature to its string representation.
var ICCMPFuncSigs = ICCMPMetaData.Sigs

// ICCMPBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ICCMPMetaData.Bin instead.
var ICCMPBin = ICCMPMetaData.Bin

// DeployICCMP deploys a new Ethereum contract, binding an instance of ICCMP to it.
func DeployICCMP(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *ICCMP, error) {
	parsed, err := ICCMPMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ICCMPBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ICCMP{ICCMPCaller: ICCMPCaller{contract: contract}, ICCMPTransactor: ICCMPTransactor{contract: contract}, ICCMPFilterer: ICCMPFilterer{contract: contract}}, nil
}

// ICCMP is an auto generated Go binding around an Ethereum contract.
type ICCMP struct {
	ICCMPCaller     // Read-only binding to the contract
	ICCMPTransactor // Write-only binding to the contract
	ICCMPFilterer   // Log filterer for contract events
}

// ICCMPCaller is an auto generated read-only Go binding around an Ethereum contract.
type ICCMPCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ICCMPTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ICCMPTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ICCMPFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ICCMPFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ICCMPSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ICCMPSession struct {
	Contract     *ICCMP            // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ICCMPCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ICCMPCallerSession struct {
	Contract *ICCMPCaller  // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// ICCMPTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ICCMPTransactorSession struct {
	Contract     *ICCMPTransactor  // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ICCMPRaw is an auto generated low-level Go binding around an Ethereum contract.
type ICCMPRaw struct {
	Contract *ICCMP // Generic contract binding to access the raw methods on
}

// ICCMPCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ICCMPCallerRaw struct {
	Contract *ICCMPCaller // Generic read-only contract binding to access the raw methods on
}

// ICCMPTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ICCMPTransactorRaw struct {
	Contract *ICCMPTransactor // Generic write-only contract binding to access the raw methods on
}

// NewICCMP creates a new instance of ICCMP, bound to a specific deployed contract.
func NewICCMP(address common.Address, backend bind.ContractBackend) (*ICCMP, error) {
	contract, err := bindICCMP(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ICCMP{ICCMPCaller: ICCMPCaller{contract: contract}, ICCMPTransactor: ICCMPTransactor{contract: contract}, ICCMPFilterer: ICCMPFilterer{contract: contract}}, nil
}

// NewICCMPCaller creates a new read-only instance of ICCMP, bound to a specific deployed contract.
func NewICCMPCaller(address common.Address, caller bind.ContractCaller) (*ICCMPCaller, error) {
	contract, err := bindICCMP(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ICCMPCaller{contract: contract}, nil
}

// NewICCMPTransactor creates a new write-only instance of ICCMP, bound to a specific deployed contract.
func NewICCMPTransactor(address common.Address, transactor bind.ContractTransactor) (*ICCMPTransactor, error) {
	contract, err := bindICCMP(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ICCMPTransactor{contract: contract}, nil
}

// NewICCMPFilterer creates a new log filterer instance of ICCMP, bound to a specific deployed contract.
func NewICCMPFilterer(address common.Address, filterer bind.ContractFilterer) (*ICCMPFilterer, error) {
	contract, err := bindICCMP(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ICCMPFilterer{contract: contract}, nil
}

// bindICCMP binds a generic wrapper to an already deployed contract.
func bindICCMP(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ICCMPABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ICCMP *ICCMPRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ICCMP.Contract.ICCMPCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ICCMP *ICCMPRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ICCMP.Contract.ICCMPTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ICCMP *ICCMPRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ICCMP.Contract.ICCMPTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ICCMP *ICCMPCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ICCMP.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ICCMP *ICCMPTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ICCMP.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ICCMP *ICCMPTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ICCMP.Contract.contract.Transact(opts, method, params...)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_ICCMP *ICCMPCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _ICCMP.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_ICCMP *ICCMPSession) Owner() (common.Address, error) {
	return _ICCMP.Contract.Owner(&_ICCMP.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_ICCMP *ICCMPCallerSession) Owner() (common.Address, error) {
	return _ICCMP.Contract.Owner(&_ICCMP.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_ICCMP *ICCMPCaller) Paused(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _ICCMP.contract.Call(opts, &out, "paused")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_ICCMP *ICCMPSession) Paused() (bool, error) {
	return _ICCMP.Contract.Paused(&_ICCMP.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_ICCMP *ICCMPCallerSession) Paused() (bool, error) {
	return _ICCMP.Contract.Paused(&_ICCMP.CallOpts)
}

// PauseEthCrossChainManager is a paid mutator transaction binding the contract method 0x3b9a80b8.
//
// Solidity: function pauseEthCrossChainManager() returns(bool)
func (_ICCMP *ICCMPTransactor) PauseEthCrossChainManager(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ICCMP.contract.Transact(opts, "pauseEthCrossChainManager")
}

// PauseEthCrossChainManager is a paid mutator transaction binding the contract method 0x3b9a80b8.
//
// Solidity: function pauseEthCrossChainManager() returns(bool)
func (_ICCMP *ICCMPSession) PauseEthCrossChainManager() (*types.Transaction, error) {
	return _ICCMP.Contract.PauseEthCrossChainManager(&_ICCMP.TransactOpts)
}

// PauseEthCrossChainManager is a paid mutator transaction binding the contract method 0x3b9a80b8.
//
// Solidity: function pauseEthCrossChainManager() returns(bool)
func (_ICCMP *ICCMPTransactorSession) PauseEthCrossChainManager() (*types.Transaction, error) {
	return _ICCMP.Contract.PauseEthCrossChainManager(&_ICCMP.TransactOpts)
}

// UnpauseEthCrossChainManager is a paid mutator transaction binding the contract method 0x4390c707.
//
// Solidity: function unpauseEthCrossChainManager() returns(bool)
func (_ICCMP *ICCMPTransactor) UnpauseEthCrossChainManager(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ICCMP.contract.Transact(opts, "unpauseEthCrossChainManager")
}

// UnpauseEthCrossChainManager is a paid mutator transaction binding the contract method 0x4390c707.
//
// Solidity: function unpauseEthCrossChainManager() returns(bool)
func (_ICCMP *ICCMPSession) UnpauseEthCrossChainManager() (*types.Transaction, error) {
	return _ICCMP.Contract.UnpauseEthCrossChainManager(&_ICCMP.TransactOpts)
}

// UnpauseEthCrossChainManager is a paid mutator transaction binding the contract method 0x4390c707.
//
// Solidity: function unpauseEthCrossChainManager() returns(bool)
func (_ICCMP *ICCMPTransactorSession) UnpauseEthCrossChainManager() (*types.Transaction, error) {
	return _ICCMP.Contract.UnpauseEthCrossChainManager(&_ICCMP.TransactOpts)
}

