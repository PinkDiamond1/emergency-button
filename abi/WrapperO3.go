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

// WrapperO3ABI is the input ABI used to generate the binding from.
const WrapperO3ABI = "[{\"constant\":false,\"inputs\":[],\"name\":\"extractFee\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

// WrapperO3FuncSigs maps the 4-byte function signature to its string representation.
var WrapperO3FuncSigs = map[string]string{
	"839b40f2": "extractFee()",
}

// WrapperO3Bin is the compiled bytecode used for deploying new contracts.
var WrapperO3Bin = "0x6080604052348015600f57600080fd5b50606c80601d6000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063839b40f214602d575b600080fd5b60336035565b005b56fea265627a7a72315820f9e3ee845e18675c19e8789b7e09b36511f941c33102b83e8a53471aac0cf98d64736f6c63430005110032"

// DeployWrapperO3 deploys a new Ethereum contract, binding an instance of WrapperO3 to it.
func DeployWrapperO3(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *WrapperO3, error) {
	parsed, err := abi.JSON(strings.NewReader(WrapperO3ABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(WrapperO3Bin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &WrapperO3{WrapperO3Caller: WrapperO3Caller{contract: contract}, WrapperO3Transactor: WrapperO3Transactor{contract: contract}, WrapperO3Filterer: WrapperO3Filterer{contract: contract}}, nil
}

// WrapperO3 is an auto generated Go binding around an Ethereum contract.
type WrapperO3 struct {
	WrapperO3Caller     // Read-only binding to the contract
	WrapperO3Transactor // Write-only binding to the contract
	WrapperO3Filterer   // Log filterer for contract events
}

// WrapperO3Caller is an auto generated read-only Go binding around an Ethereum contract.
type WrapperO3Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// WrapperO3Transactor is an auto generated write-only Go binding around an Ethereum contract.
type WrapperO3Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// WrapperO3Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type WrapperO3Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// WrapperO3Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type WrapperO3Session struct {
	Contract     *WrapperO3        // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// WrapperO3CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type WrapperO3CallerSession struct {
	Contract *WrapperO3Caller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts    // Call options to use throughout this session
}

// WrapperO3TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type WrapperO3TransactorSession struct {
	Contract     *WrapperO3Transactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// WrapperO3Raw is an auto generated low-level Go binding around an Ethereum contract.
type WrapperO3Raw struct {
	Contract *WrapperO3 // Generic contract binding to access the raw methods on
}

// WrapperO3CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type WrapperO3CallerRaw struct {
	Contract *WrapperO3Caller // Generic read-only contract binding to access the raw methods on
}

// WrapperO3TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type WrapperO3TransactorRaw struct {
	Contract *WrapperO3Transactor // Generic write-only contract binding to access the raw methods on
}

// NewWrapperO3 creates a new instance of WrapperO3, bound to a specific deployed contract.
func NewWrapperO3(address common.Address, backend bind.ContractBackend) (*WrapperO3, error) {
	contract, err := bindWrapperO3(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &WrapperO3{WrapperO3Caller: WrapperO3Caller{contract: contract}, WrapperO3Transactor: WrapperO3Transactor{contract: contract}, WrapperO3Filterer: WrapperO3Filterer{contract: contract}}, nil
}

// NewWrapperO3Caller creates a new read-only instance of WrapperO3, bound to a specific deployed contract.
func NewWrapperO3Caller(address common.Address, caller bind.ContractCaller) (*WrapperO3Caller, error) {
	contract, err := bindWrapperO3(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &WrapperO3Caller{contract: contract}, nil
}

// NewWrapperO3Transactor creates a new write-only instance of WrapperO3, bound to a specific deployed contract.
func NewWrapperO3Transactor(address common.Address, transactor bind.ContractTransactor) (*WrapperO3Transactor, error) {
	contract, err := bindWrapperO3(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &WrapperO3Transactor{contract: contract}, nil
}

// NewWrapperO3Filterer creates a new log filterer instance of WrapperO3, bound to a specific deployed contract.
func NewWrapperO3Filterer(address common.Address, filterer bind.ContractFilterer) (*WrapperO3Filterer, error) {
	contract, err := bindWrapperO3(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &WrapperO3Filterer{contract: contract}, nil
}

// bindWrapperO3 binds a generic wrapper to an already deployed contract.
func bindWrapperO3(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(WrapperO3ABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_WrapperO3 *WrapperO3Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _WrapperO3.Contract.WrapperO3Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_WrapperO3 *WrapperO3Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _WrapperO3.Contract.WrapperO3Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_WrapperO3 *WrapperO3Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _WrapperO3.Contract.WrapperO3Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_WrapperO3 *WrapperO3CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _WrapperO3.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_WrapperO3 *WrapperO3TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _WrapperO3.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_WrapperO3 *WrapperO3TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _WrapperO3.Contract.contract.Transact(opts, method, params...)
}

// ExtractFee is a paid mutator transaction binding the contract method 0x839b40f2.
//
// Solidity: function extractFee() returns()
func (_WrapperO3 *WrapperO3Transactor) ExtractFee(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _WrapperO3.contract.Transact(opts, "extractFee")
}

// ExtractFee is a paid mutator transaction binding the contract method 0x839b40f2.
//
// Solidity: function extractFee() returns()
func (_WrapperO3 *WrapperO3Session) ExtractFee() (*types.Transaction, error) {
	return _WrapperO3.Contract.ExtractFee(&_WrapperO3.TransactOpts)
}

// ExtractFee is a paid mutator transaction binding the contract method 0x839b40f2.
//
// Solidity: function extractFee() returns()
func (_WrapperO3 *WrapperO3TransactorSession) ExtractFee() (*types.Transaction, error) {
	return _WrapperO3.Contract.ExtractFee(&_WrapperO3.TransactOpts)
}

