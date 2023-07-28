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

// ILockProxyWithLPABI is the input ABI used to generate the binding from.
const ILockProxyWithLPABI = "[{\"constant\":true,\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"uint64\",\"name\":\"\",\"type\":\"uint64\"}],\"name\":\"assetHashMap\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"assetLPMap\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"fromAssetHash\",\"type\":\"address\"},{\"internalType\":\"uint64\",\"name\":\"toChainId\",\"type\":\"uint64\"},{\"internalType\":\"bytes\",\"name\":\"toAssetHash\",\"type\":\"bytes\"}],\"name\":\"bindAssetHash\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"fromAssetHash\",\"type\":\"address[]\"},{\"internalType\":\"uint64[]\",\"name\":\"toChainId\",\"type\":\"uint64[]\"},{\"internalType\":\"bytes[]\",\"name\":\"toAssetHash\",\"type\":\"bytes[]\"}],\"name\":\"bindAssetHashBatch\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"fromAssetHash\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"fromLPHash\",\"type\":\"address\"},{\"internalType\":\"uint64\",\"name\":\"toChainId\",\"type\":\"uint64\"},{\"internalType\":\"bytes\",\"name\":\"toAssetHash\",\"type\":\"bytes\"},{\"internalType\":\"bytes\",\"name\":\"toLPHash\",\"type\":\"bytes\"}],\"name\":\"bindLPAndAsset\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"fromAssetHash\",\"type\":\"address[]\"},{\"internalType\":\"address[]\",\"name\":\"fromLPHash\",\"type\":\"address[]\"},{\"internalType\":\"uint64[]\",\"name\":\"toChainId\",\"type\":\"uint64[]\"},{\"internalType\":\"bytes[]\",\"name\":\"toAssetHash\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes[]\",\"name\":\"toLPHash\",\"type\":\"bytes[]\"}],\"name\":\"bindLPAndAssetBatch\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"originAssetAddress\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"LPTokenAddress\",\"type\":\"address\"}],\"name\":\"bindLPToAsset\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"originAssetAddress\",\"type\":\"address[]\"},{\"internalType\":\"address[]\",\"name\":\"LPTokenAddress\",\"type\":\"address[]\"}],\"name\":\"bindLPToAssetBatch\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"toChainId\",\"type\":\"uint64\"},{\"internalType\":\"bytes\",\"name\":\"targetProxyHash\",\"type\":\"bytes\"}],\"name\":\"bindProxyHash\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"uint64[]\",\"name\":\"toChainId\",\"type\":\"uint64[]\"},{\"internalType\":\"bytes[]\",\"name\":\"targetProxyHash\",\"type\":\"bytes[]\"}],\"name\":\"bindProxyHashBatch\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"originAssetAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"deposit\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"internalType\":\"address\",\"name\":\"fromAssetHash\",\"type\":\"address\"}],\"name\":\"getBalanceFor\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"pause\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"\",\"type\":\"uint64\"}],\"name\":\"proxyHashMap\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"unpause\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"internalType\":\"address\",\"name\":\"targetTokenAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"withdraw\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

// ILockProxyWithLPFuncSigs maps the 4-byte function signature to its string representation.
var ILockProxyWithLPFuncSigs = map[string]string{
	"4f7d9808": "assetHashMap(address,uint64)",
	"3389279d": "assetLPMap(address)",
	"3348f63b": "bindAssetHash(address,uint64,bytes)",
	"6f3326d5": "bindAssetHashBatch(address[],uint64[],bytes[])",
	"53d1d277": "bindLPAndAsset(address,address,uint64,bytes,bytes)",
	"0892cf48": "bindLPAndAssetBatch(address[],address[],uint64[],bytes[],bytes[])",
	"6bc9e760": "bindLPToAsset(address,address)",
	"61c6617d": "bindLPToAssetBatch(address[],address[])",
	"379b98f6": "bindProxyHash(uint64,bytes)",
	"25a9f900": "bindProxyHashBatch(uint64[],bytes[])",
	"47e7ef24": "deposit(address,uint256)",
	"59c589a1": "getBalanceFor(address)",
	"8456cb59": "pause()",
	"9e5767aa": "proxyHashMap(uint64)",
	"3f4ba83a": "unpause()",
	"f3fef3a3": "withdraw(address,uint256)",
}

// ILockProxyWithLPBin is the compiled bytecode used for deploying new contracts.
var ILockProxyWithLPBin = "0x608060405234801561001057600080fd5b50610c22806100206000396000f3fe6080604052600436106100f35760003560e01c806353d1d2771161008a5780636f3326d5116100595780636f3326d5146102845780638456cb59146101b65780639e5767aa1461029f578063f3fef3a3146102bf576100f3565b806353d1d2771461020657806359c589a11461022157806361c6617d1461024e5780636bc9e76014610269576100f3565b8063379b98f6116100c6578063379b98f61461019b5780633f4ba83a146101b657806347e7ef24146101cb5780634f7d9808146101d9576100f3565b80630892cf48146100f857806325a9f9001461012e5780633348f63b1461014e5780633389279d1461016e575b600080fd5b34801561010457600080fd5b5061011861011336600461080d565b6102da565b6040516101259190610a97565b60405180910390f35b34801561013a57600080fd5b5061011861014936600461096e565b6102e5565b34801561015a57600080fd5b5061011861016936600461074c565b6102ed565b34801561017a57600080fd5b5061018e6101893660046105e9565b6102f6565b6040516101259190610a89565b3480156101a757600080fd5b506101186101493660046109e9565b3480156101c257600080fd5b50610118610311565b6101186101493660046106ec565b3480156101e557600080fd5b506101f96101f436600461071c565b610316565b6040516101259190610aa5565b34801561021257600080fd5b50610118610113366004610649565b34801561022d57600080fd5b5061024161023c3660046105e9565b6103ba565b6040516101259190610abd565b34801561025a57600080fd5b506101186101493660046107b0565b34801561027557600080fd5b5061011861014936600461060f565b34801561029057600080fd5b506101186101693660046108e7565b3480156102ab57600080fd5b506101f96102ba3660046109cb565b6103c0565b3480156102cb57600080fd5b506101186101493660046106ec565b600095945050505050565b600092915050565b60009392505050565b6002602052600090815260409020546001600160a01b031681565b600090565b600160208181526000938452604080852082529284529282902080548351600293821615610100026000190190911692909204601f810185900485028301850190935282825290929091908301828280156103b25780601f10610387576101008083540402835291602001916103b2565b820191906000526020600020905b81548152906001019060200180831161039557829003601f168201915b505050505081565b50600090565b600060208181529181526040908190208054825160026001831615610100026000190190921691909104601f8101859004850282018501909352828152929091908301828280156103b25780601f10610387576101008083540402835291602001916103b2565b803561043281610bb6565b92915050565b600082601f83011261044957600080fd5b813561045c61045782610af1565b610acb565b9150818183526020840193506020810190508385602084028201111561048157600080fd5b60005b838110156104ad57816104978882610427565b8452506020928301929190910190600101610484565b5050505092915050565b600082601f8301126104c857600080fd5b81356104d661045782610af1565b81815260209384019390925082018360005b838110156104ad57813586016104fe8882610584565b84525060209283019291909101906001016104e8565b600082601f83011261052557600080fd5b813561053361045782610af1565b9150818183526020840193506020810190508385602084028201111561055857600080fd5b60005b838110156104ad578161056e88826105de565b845250602092830192919091019060010161055b565b600082601f83011261059557600080fd5b81356105a361045782610b11565b915080825260208301602083018583830111156105bf57600080fd5b6105ca838284610b70565b50505092915050565b803561043281610bcd565b803561043281610bd6565b6000602082840312156105fb57600080fd5b60006106078484610427565b949350505050565b6000806040838503121561062257600080fd5b600061062e8585610427565b925050602061063f85828601610427565b9150509250929050565b600080600080600060a0868803121561066157600080fd5b600061066d8888610427565b955050602061067e88828901610427565b945050604061068f888289016105de565b93505060608601356001600160401b038111156106ab57600080fd5b6106b788828901610584565b92505060808601356001600160401b038111156106d357600080fd5b6106df88828901610584565b9150509295509295909350565b600080604083850312156106ff57600080fd5b600061070b8585610427565b925050602061063f858286016105d3565b6000806040838503121561072f57600080fd5b600061073b8585610427565b925050602061063f858286016105de565b60008060006060848603121561076157600080fd5b600061076d8686610427565b935050602061077e868287016105de565b92505060408401356001600160401b0381111561079a57600080fd5b6107a686828701610584565b9150509250925092565b600080604083850312156107c357600080fd5b82356001600160401b038111156107d957600080fd5b6107e585828601610438565b92505060208301356001600160401b0381111561080157600080fd5b61063f85828601610438565b600080600080600060a0868803121561082557600080fd5b85356001600160401b0381111561083b57600080fd5b61084788828901610438565b95505060208601356001600160401b0381111561086357600080fd5b61086f88828901610438565b94505060408601356001600160401b0381111561088b57600080fd5b61089788828901610514565b93505060608601356001600160401b038111156108b357600080fd5b6108bf888289016104b7565b92505060808601356001600160401b038111156108db57600080fd5b6106df888289016104b7565b6000806000606084860312156108fc57600080fd5b83356001600160401b0381111561091257600080fd5b61091e86828701610438565b93505060208401356001600160401b0381111561093a57600080fd5b61094686828701610514565b92505060408401356001600160401b0381111561096257600080fd5b6107a6868287016104b7565b6000806040838503121561098157600080fd5b82356001600160401b0381111561099757600080fd5b6109a385828601610514565b92505060208301356001600160401b038111156109bf57600080fd5b61063f858286016104b7565b6000602082840312156109dd57600080fd5b600061060784846105de565b600080604083850312156109fc57600080fd5b6000610a0885856105de565b92505060208301356001600160401b03811115610a2457600080fd5b61063f85828601610584565b610a3981610b45565b82525050565b610a3981610b50565b6000610a5382610b38565b610a5d8185610b3c565b9350610a6d818560208601610b7c565b610a7681610bac565b9093019392505050565b610a3981610b61565b602081016104328284610a30565b602081016104328284610a3f565b60208082528101610ab68184610a48565b9392505050565b602081016104328284610a80565b6040518181016001600160401b0381118282101715610ae957600080fd5b604052919050565b60006001600160401b03821115610b0757600080fd5b5060209081020190565b60006001600160401b03821115610b2757600080fd5b506020601f91909101601f19160190565b5190565b90815260200190565b600061043282610b55565b151590565b6001600160a01b031690565b90565b6001600160401b031690565b82818337506000910152565b60005b83811015610b97578181015183820152602001610b7f565b83811115610ba6576000848401525b50505050565b601f01601f191690565b610bbf81610b45565b8114610bca57600080fd5b50565b610bbf81610b61565b610bbf81610b6456fea365627a7a7231582056cbb554ee59f5bab9d5a8b3a2d29672f4b0b84b1e93c5dc62946beb7a050ac06c6578706572696d656e74616cf564736f6c63430005110040"

// DeployILockProxyWithLP deploys a new Ethereum contract, binding an instance of ILockProxyWithLP to it.
func DeployILockProxyWithLP(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *ILockProxyWithLP, error) {
	parsed, err := abi.JSON(strings.NewReader(ILockProxyWithLPABI))
	if err != nil {
		return common.Address{}, nil, nil, err
	}

	address, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(ILockProxyWithLPBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &ILockProxyWithLP{ILockProxyWithLPCaller: ILockProxyWithLPCaller{contract: contract}, ILockProxyWithLPTransactor: ILockProxyWithLPTransactor{contract: contract}, ILockProxyWithLPFilterer: ILockProxyWithLPFilterer{contract: contract}}, nil
}

// ILockProxyWithLP is an auto generated Go binding around an Ethereum contract.
type ILockProxyWithLP struct {
	ILockProxyWithLPCaller     // Read-only binding to the contract
	ILockProxyWithLPTransactor // Write-only binding to the contract
	ILockProxyWithLPFilterer   // Log filterer for contract events
}

// ILockProxyWithLPCaller is an auto generated read-only Go binding around an Ethereum contract.
type ILockProxyWithLPCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ILockProxyWithLPTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ILockProxyWithLPTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ILockProxyWithLPFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ILockProxyWithLPFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ILockProxyWithLPSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ILockProxyWithLPSession struct {
	Contract     *ILockProxyWithLP // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ILockProxyWithLPCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ILockProxyWithLPCallerSession struct {
	Contract *ILockProxyWithLPCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts           // Call options to use throughout this session
}

// ILockProxyWithLPTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ILockProxyWithLPTransactorSession struct {
	Contract     *ILockProxyWithLPTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts           // Transaction auth options to use throughout this session
}

// ILockProxyWithLPRaw is an auto generated low-level Go binding around an Ethereum contract.
type ILockProxyWithLPRaw struct {
	Contract *ILockProxyWithLP // Generic contract binding to access the raw methods on
}

// ILockProxyWithLPCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ILockProxyWithLPCallerRaw struct {
	Contract *ILockProxyWithLPCaller // Generic read-only contract binding to access the raw methods on
}

// ILockProxyWithLPTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ILockProxyWithLPTransactorRaw struct {
	Contract *ILockProxyWithLPTransactor // Generic write-only contract binding to access the raw methods on
}

// NewILockProxyWithLP creates a new instance of ILockProxyWithLP, bound to a specific deployed contract.
func NewILockProxyWithLP(address common.Address, backend bind.ContractBackend) (*ILockProxyWithLP, error) {
	contract, err := bindILockProxyWithLP(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &ILockProxyWithLP{ILockProxyWithLPCaller: ILockProxyWithLPCaller{contract: contract}, ILockProxyWithLPTransactor: ILockProxyWithLPTransactor{contract: contract}, ILockProxyWithLPFilterer: ILockProxyWithLPFilterer{contract: contract}}, nil
}

// NewILockProxyWithLPCaller creates a new read-only instance of ILockProxyWithLP, bound to a specific deployed contract.
func NewILockProxyWithLPCaller(address common.Address, caller bind.ContractCaller) (*ILockProxyWithLPCaller, error) {
	contract, err := bindILockProxyWithLP(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ILockProxyWithLPCaller{contract: contract}, nil
}

// NewILockProxyWithLPTransactor creates a new write-only instance of ILockProxyWithLP, bound to a specific deployed contract.
func NewILockProxyWithLPTransactor(address common.Address, transactor bind.ContractTransactor) (*ILockProxyWithLPTransactor, error) {
	contract, err := bindILockProxyWithLP(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ILockProxyWithLPTransactor{contract: contract}, nil
}

// NewILockProxyWithLPFilterer creates a new log filterer instance of ILockProxyWithLP, bound to a specific deployed contract.
func NewILockProxyWithLPFilterer(address common.Address, filterer bind.ContractFilterer) (*ILockProxyWithLPFilterer, error) {
	contract, err := bindILockProxyWithLP(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ILockProxyWithLPFilterer{contract: contract}, nil
}

// bindILockProxyWithLP binds a generic wrapper to an already deployed contract.
func bindILockProxyWithLP(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ILockProxyWithLPABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ILockProxyWithLP *ILockProxyWithLPRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ILockProxyWithLP.Contract.ILockProxyWithLPCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ILockProxyWithLP *ILockProxyWithLPRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.ILockProxyWithLPTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ILockProxyWithLP *ILockProxyWithLPRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.ILockProxyWithLPTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_ILockProxyWithLP *ILockProxyWithLPCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _ILockProxyWithLP.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_ILockProxyWithLP *ILockProxyWithLPTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_ILockProxyWithLP *ILockProxyWithLPTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.contract.Transact(opts, method, params...)
}

// AssetHashMap is a free data retrieval call binding the contract method 0x4f7d9808.
//
// Solidity: function assetHashMap(address , uint64 ) view returns(bytes)
func (_ILockProxyWithLP *ILockProxyWithLPCaller) AssetHashMap(opts *bind.CallOpts, arg0 common.Address, arg1 uint64) ([]byte, error) {
	var out []interface{}
	err := _ILockProxyWithLP.contract.Call(opts, &out, "assetHashMap", arg0, arg1)

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// AssetHashMap is a free data retrieval call binding the contract method 0x4f7d9808.
//
// Solidity: function assetHashMap(address , uint64 ) view returns(bytes)
func (_ILockProxyWithLP *ILockProxyWithLPSession) AssetHashMap(arg0 common.Address, arg1 uint64) ([]byte, error) {
	return _ILockProxyWithLP.Contract.AssetHashMap(&_ILockProxyWithLP.CallOpts, arg0, arg1)
}

// AssetHashMap is a free data retrieval call binding the contract method 0x4f7d9808.
//
// Solidity: function assetHashMap(address , uint64 ) view returns(bytes)
func (_ILockProxyWithLP *ILockProxyWithLPCallerSession) AssetHashMap(arg0 common.Address, arg1 uint64) ([]byte, error) {
	return _ILockProxyWithLP.Contract.AssetHashMap(&_ILockProxyWithLP.CallOpts, arg0, arg1)
}

// AssetLPMap is a free data retrieval call binding the contract method 0x3389279d.
//
// Solidity: function assetLPMap(address ) view returns(address)
func (_ILockProxyWithLP *ILockProxyWithLPCaller) AssetLPMap(opts *bind.CallOpts, arg0 common.Address) (common.Address, error) {
	var out []interface{}
	err := _ILockProxyWithLP.contract.Call(opts, &out, "assetLPMap", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// AssetLPMap is a free data retrieval call binding the contract method 0x3389279d.
//
// Solidity: function assetLPMap(address ) view returns(address)
func (_ILockProxyWithLP *ILockProxyWithLPSession) AssetLPMap(arg0 common.Address) (common.Address, error) {
	return _ILockProxyWithLP.Contract.AssetLPMap(&_ILockProxyWithLP.CallOpts, arg0)
}

// AssetLPMap is a free data retrieval call binding the contract method 0x3389279d.
//
// Solidity: function assetLPMap(address ) view returns(address)
func (_ILockProxyWithLP *ILockProxyWithLPCallerSession) AssetLPMap(arg0 common.Address) (common.Address, error) {
	return _ILockProxyWithLP.Contract.AssetLPMap(&_ILockProxyWithLP.CallOpts, arg0)
}

// GetBalanceFor is a free data retrieval call binding the contract method 0x59c589a1.
//
// Solidity: function getBalanceFor(address fromAssetHash) view returns(uint256)
func (_ILockProxyWithLP *ILockProxyWithLPCaller) GetBalanceFor(opts *bind.CallOpts, fromAssetHash common.Address) (*big.Int, error) {
	var out []interface{}
	err := _ILockProxyWithLP.contract.Call(opts, &out, "getBalanceFor", fromAssetHash)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetBalanceFor is a free data retrieval call binding the contract method 0x59c589a1.
//
// Solidity: function getBalanceFor(address fromAssetHash) view returns(uint256)
func (_ILockProxyWithLP *ILockProxyWithLPSession) GetBalanceFor(fromAssetHash common.Address) (*big.Int, error) {
	return _ILockProxyWithLP.Contract.GetBalanceFor(&_ILockProxyWithLP.CallOpts, fromAssetHash)
}

// GetBalanceFor is a free data retrieval call binding the contract method 0x59c589a1.
//
// Solidity: function getBalanceFor(address fromAssetHash) view returns(uint256)
func (_ILockProxyWithLP *ILockProxyWithLPCallerSession) GetBalanceFor(fromAssetHash common.Address) (*big.Int, error) {
	return _ILockProxyWithLP.Contract.GetBalanceFor(&_ILockProxyWithLP.CallOpts, fromAssetHash)
}

// ProxyHashMap is a free data retrieval call binding the contract method 0x9e5767aa.
//
// Solidity: function proxyHashMap(uint64 ) view returns(bytes)
func (_ILockProxyWithLP *ILockProxyWithLPCaller) ProxyHashMap(opts *bind.CallOpts, arg0 uint64) ([]byte, error) {
	var out []interface{}
	err := _ILockProxyWithLP.contract.Call(opts, &out, "proxyHashMap", arg0)

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// ProxyHashMap is a free data retrieval call binding the contract method 0x9e5767aa.
//
// Solidity: function proxyHashMap(uint64 ) view returns(bytes)
func (_ILockProxyWithLP *ILockProxyWithLPSession) ProxyHashMap(arg0 uint64) ([]byte, error) {
	return _ILockProxyWithLP.Contract.ProxyHashMap(&_ILockProxyWithLP.CallOpts, arg0)
}

// ProxyHashMap is a free data retrieval call binding the contract method 0x9e5767aa.
//
// Solidity: function proxyHashMap(uint64 ) view returns(bytes)
func (_ILockProxyWithLP *ILockProxyWithLPCallerSession) ProxyHashMap(arg0 uint64) ([]byte, error) {
	return _ILockProxyWithLP.Contract.ProxyHashMap(&_ILockProxyWithLP.CallOpts, arg0)
}

// BindAssetHash is a paid mutator transaction binding the contract method 0x3348f63b.
//
// Solidity: function bindAssetHash(address fromAssetHash, uint64 toChainId, bytes toAssetHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) BindAssetHash(opts *bind.TransactOpts, fromAssetHash common.Address, toChainId uint64, toAssetHash []byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "bindAssetHash", fromAssetHash, toChainId, toAssetHash)
}

// BindAssetHash is a paid mutator transaction binding the contract method 0x3348f63b.
//
// Solidity: function bindAssetHash(address fromAssetHash, uint64 toChainId, bytes toAssetHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) BindAssetHash(fromAssetHash common.Address, toChainId uint64, toAssetHash []byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindAssetHash(&_ILockProxyWithLP.TransactOpts, fromAssetHash, toChainId, toAssetHash)
}

// BindAssetHash is a paid mutator transaction binding the contract method 0x3348f63b.
//
// Solidity: function bindAssetHash(address fromAssetHash, uint64 toChainId, bytes toAssetHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) BindAssetHash(fromAssetHash common.Address, toChainId uint64, toAssetHash []byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindAssetHash(&_ILockProxyWithLP.TransactOpts, fromAssetHash, toChainId, toAssetHash)
}

// BindAssetHashBatch is a paid mutator transaction binding the contract method 0x6f3326d5.
//
// Solidity: function bindAssetHashBatch(address[] fromAssetHash, uint64[] toChainId, bytes[] toAssetHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) BindAssetHashBatch(opts *bind.TransactOpts, fromAssetHash []common.Address, toChainId []uint64, toAssetHash [][]byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "bindAssetHashBatch", fromAssetHash, toChainId, toAssetHash)
}

// BindAssetHashBatch is a paid mutator transaction binding the contract method 0x6f3326d5.
//
// Solidity: function bindAssetHashBatch(address[] fromAssetHash, uint64[] toChainId, bytes[] toAssetHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) BindAssetHashBatch(fromAssetHash []common.Address, toChainId []uint64, toAssetHash [][]byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindAssetHashBatch(&_ILockProxyWithLP.TransactOpts, fromAssetHash, toChainId, toAssetHash)
}

// BindAssetHashBatch is a paid mutator transaction binding the contract method 0x6f3326d5.
//
// Solidity: function bindAssetHashBatch(address[] fromAssetHash, uint64[] toChainId, bytes[] toAssetHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) BindAssetHashBatch(fromAssetHash []common.Address, toChainId []uint64, toAssetHash [][]byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindAssetHashBatch(&_ILockProxyWithLP.TransactOpts, fromAssetHash, toChainId, toAssetHash)
}

// BindLPAndAsset is a paid mutator transaction binding the contract method 0x53d1d277.
//
// Solidity: function bindLPAndAsset(address fromAssetHash, address fromLPHash, uint64 toChainId, bytes toAssetHash, bytes toLPHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) BindLPAndAsset(opts *bind.TransactOpts, fromAssetHash common.Address, fromLPHash common.Address, toChainId uint64, toAssetHash []byte, toLPHash []byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "bindLPAndAsset", fromAssetHash, fromLPHash, toChainId, toAssetHash, toLPHash)
}

// BindLPAndAsset is a paid mutator transaction binding the contract method 0x53d1d277.
//
// Solidity: function bindLPAndAsset(address fromAssetHash, address fromLPHash, uint64 toChainId, bytes toAssetHash, bytes toLPHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) BindLPAndAsset(fromAssetHash common.Address, fromLPHash common.Address, toChainId uint64, toAssetHash []byte, toLPHash []byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindLPAndAsset(&_ILockProxyWithLP.TransactOpts, fromAssetHash, fromLPHash, toChainId, toAssetHash, toLPHash)
}

// BindLPAndAsset is a paid mutator transaction binding the contract method 0x53d1d277.
//
// Solidity: function bindLPAndAsset(address fromAssetHash, address fromLPHash, uint64 toChainId, bytes toAssetHash, bytes toLPHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) BindLPAndAsset(fromAssetHash common.Address, fromLPHash common.Address, toChainId uint64, toAssetHash []byte, toLPHash []byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindLPAndAsset(&_ILockProxyWithLP.TransactOpts, fromAssetHash, fromLPHash, toChainId, toAssetHash, toLPHash)
}

// BindLPAndAssetBatch is a paid mutator transaction binding the contract method 0x0892cf48.
//
// Solidity: function bindLPAndAssetBatch(address[] fromAssetHash, address[] fromLPHash, uint64[] toChainId, bytes[] toAssetHash, bytes[] toLPHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) BindLPAndAssetBatch(opts *bind.TransactOpts, fromAssetHash []common.Address, fromLPHash []common.Address, toChainId []uint64, toAssetHash [][]byte, toLPHash [][]byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "bindLPAndAssetBatch", fromAssetHash, fromLPHash, toChainId, toAssetHash, toLPHash)
}

// BindLPAndAssetBatch is a paid mutator transaction binding the contract method 0x0892cf48.
//
// Solidity: function bindLPAndAssetBatch(address[] fromAssetHash, address[] fromLPHash, uint64[] toChainId, bytes[] toAssetHash, bytes[] toLPHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) BindLPAndAssetBatch(fromAssetHash []common.Address, fromLPHash []common.Address, toChainId []uint64, toAssetHash [][]byte, toLPHash [][]byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindLPAndAssetBatch(&_ILockProxyWithLP.TransactOpts, fromAssetHash, fromLPHash, toChainId, toAssetHash, toLPHash)
}

// BindLPAndAssetBatch is a paid mutator transaction binding the contract method 0x0892cf48.
//
// Solidity: function bindLPAndAssetBatch(address[] fromAssetHash, address[] fromLPHash, uint64[] toChainId, bytes[] toAssetHash, bytes[] toLPHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) BindLPAndAssetBatch(fromAssetHash []common.Address, fromLPHash []common.Address, toChainId []uint64, toAssetHash [][]byte, toLPHash [][]byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindLPAndAssetBatch(&_ILockProxyWithLP.TransactOpts, fromAssetHash, fromLPHash, toChainId, toAssetHash, toLPHash)
}

// BindLPToAsset is a paid mutator transaction binding the contract method 0x6bc9e760.
//
// Solidity: function bindLPToAsset(address originAssetAddress, address LPTokenAddress) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) BindLPToAsset(opts *bind.TransactOpts, originAssetAddress common.Address, LPTokenAddress common.Address) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "bindLPToAsset", originAssetAddress, LPTokenAddress)
}

// BindLPToAsset is a paid mutator transaction binding the contract method 0x6bc9e760.
//
// Solidity: function bindLPToAsset(address originAssetAddress, address LPTokenAddress) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) BindLPToAsset(originAssetAddress common.Address, LPTokenAddress common.Address) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindLPToAsset(&_ILockProxyWithLP.TransactOpts, originAssetAddress, LPTokenAddress)
}

// BindLPToAsset is a paid mutator transaction binding the contract method 0x6bc9e760.
//
// Solidity: function bindLPToAsset(address originAssetAddress, address LPTokenAddress) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) BindLPToAsset(originAssetAddress common.Address, LPTokenAddress common.Address) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindLPToAsset(&_ILockProxyWithLP.TransactOpts, originAssetAddress, LPTokenAddress)
}

// BindLPToAssetBatch is a paid mutator transaction binding the contract method 0x61c6617d.
//
// Solidity: function bindLPToAssetBatch(address[] originAssetAddress, address[] LPTokenAddress) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) BindLPToAssetBatch(opts *bind.TransactOpts, originAssetAddress []common.Address, LPTokenAddress []common.Address) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "bindLPToAssetBatch", originAssetAddress, LPTokenAddress)
}

// BindLPToAssetBatch is a paid mutator transaction binding the contract method 0x61c6617d.
//
// Solidity: function bindLPToAssetBatch(address[] originAssetAddress, address[] LPTokenAddress) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) BindLPToAssetBatch(originAssetAddress []common.Address, LPTokenAddress []common.Address) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindLPToAssetBatch(&_ILockProxyWithLP.TransactOpts, originAssetAddress, LPTokenAddress)
}

// BindLPToAssetBatch is a paid mutator transaction binding the contract method 0x61c6617d.
//
// Solidity: function bindLPToAssetBatch(address[] originAssetAddress, address[] LPTokenAddress) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) BindLPToAssetBatch(originAssetAddress []common.Address, LPTokenAddress []common.Address) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindLPToAssetBatch(&_ILockProxyWithLP.TransactOpts, originAssetAddress, LPTokenAddress)
}

// BindProxyHash is a paid mutator transaction binding the contract method 0x379b98f6.
//
// Solidity: function bindProxyHash(uint64 toChainId, bytes targetProxyHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) BindProxyHash(opts *bind.TransactOpts, toChainId uint64, targetProxyHash []byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "bindProxyHash", toChainId, targetProxyHash)
}

// BindProxyHash is a paid mutator transaction binding the contract method 0x379b98f6.
//
// Solidity: function bindProxyHash(uint64 toChainId, bytes targetProxyHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) BindProxyHash(toChainId uint64, targetProxyHash []byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindProxyHash(&_ILockProxyWithLP.TransactOpts, toChainId, targetProxyHash)
}

// BindProxyHash is a paid mutator transaction binding the contract method 0x379b98f6.
//
// Solidity: function bindProxyHash(uint64 toChainId, bytes targetProxyHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) BindProxyHash(toChainId uint64, targetProxyHash []byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindProxyHash(&_ILockProxyWithLP.TransactOpts, toChainId, targetProxyHash)
}

// BindProxyHashBatch is a paid mutator transaction binding the contract method 0x25a9f900.
//
// Solidity: function bindProxyHashBatch(uint64[] toChainId, bytes[] targetProxyHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) BindProxyHashBatch(opts *bind.TransactOpts, toChainId []uint64, targetProxyHash [][]byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "bindProxyHashBatch", toChainId, targetProxyHash)
}

// BindProxyHashBatch is a paid mutator transaction binding the contract method 0x25a9f900.
//
// Solidity: function bindProxyHashBatch(uint64[] toChainId, bytes[] targetProxyHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) BindProxyHashBatch(toChainId []uint64, targetProxyHash [][]byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindProxyHashBatch(&_ILockProxyWithLP.TransactOpts, toChainId, targetProxyHash)
}

// BindProxyHashBatch is a paid mutator transaction binding the contract method 0x25a9f900.
//
// Solidity: function bindProxyHashBatch(uint64[] toChainId, bytes[] targetProxyHash) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) BindProxyHashBatch(toChainId []uint64, targetProxyHash [][]byte) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.BindProxyHashBatch(&_ILockProxyWithLP.TransactOpts, toChainId, targetProxyHash)
}

// Deposit is a paid mutator transaction binding the contract method 0x47e7ef24.
//
// Solidity: function deposit(address originAssetAddress, uint256 amount) payable returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) Deposit(opts *bind.TransactOpts, originAssetAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "deposit", originAssetAddress, amount)
}

// Deposit is a paid mutator transaction binding the contract method 0x47e7ef24.
//
// Solidity: function deposit(address originAssetAddress, uint256 amount) payable returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) Deposit(originAssetAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.Deposit(&_ILockProxyWithLP.TransactOpts, originAssetAddress, amount)
}

// Deposit is a paid mutator transaction binding the contract method 0x47e7ef24.
//
// Solidity: function deposit(address originAssetAddress, uint256 amount) payable returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) Deposit(originAssetAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.Deposit(&_ILockProxyWithLP.TransactOpts, originAssetAddress, amount)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) Pause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) Pause() (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.Pause(&_ILockProxyWithLP.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) Pause() (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.Pause(&_ILockProxyWithLP.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) Unpause() (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.Unpause(&_ILockProxyWithLP.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) Unpause() (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.Unpause(&_ILockProxyWithLP.TransactOpts)
}

// Withdraw is a paid mutator transaction binding the contract method 0xf3fef3a3.
//
// Solidity: function withdraw(address targetTokenAddress, uint256 amount) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactor) Withdraw(opts *bind.TransactOpts, targetTokenAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _ILockProxyWithLP.contract.Transact(opts, "withdraw", targetTokenAddress, amount)
}

// Withdraw is a paid mutator transaction binding the contract method 0xf3fef3a3.
//
// Solidity: function withdraw(address targetTokenAddress, uint256 amount) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPSession) Withdraw(targetTokenAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.Withdraw(&_ILockProxyWithLP.TransactOpts, targetTokenAddress, amount)
}

// Withdraw is a paid mutator transaction binding the contract method 0xf3fef3a3.
//
// Solidity: function withdraw(address targetTokenAddress, uint256 amount) returns(bool)
func (_ILockProxyWithLP *ILockProxyWithLPTransactorSession) Withdraw(targetTokenAddress common.Address, amount *big.Int) (*types.Transaction, error) {
	return _ILockProxyWithLP.Contract.Withdraw(&_ILockProxyWithLP.TransactOpts, targetTokenAddress, amount)
}

