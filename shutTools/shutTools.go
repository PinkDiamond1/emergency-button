package shutTools

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/polynetwork/emergency-button/abi"

	"github.com/ethereum/go-ethereum"
	eabi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

var MultipleDecimal uint64 = 100

var DefaultGasLimitMultiple uint64 = 300
var DefaultGasPriceMultiple int64 = 200

var ADDRESS_ZERO common.Address = common.HexToAddress("0x0000000000000000000000000000000000000000")

var GasPriceList []int64 = []int64{10, 100, 500, 1000}
var Gwei int64 = 1000000000

type TransactionWithSig struct {
	Transaction types.Transaction
	Sender      string
	Raw         string
	Hash        string
	Sig         string
}

type TransactionList struct {
	PolyChainID uint64
	TxList      []TransactionWithSig
}

type TxConfig struct {
	Txns []TransactionList
}

func (c *TxConfig) GetTxns(index uint64) (txList *TransactionList) {
	for i := 0; i < len(c.Txns); i++ {
		if c.Txns[i].PolyChainID == index {
			return &c.Txns[i]
		}
	}
	return nil
}

// CCM
func Sign(msg []byte, privateKey *ecdsa.PrivateKey) (sig []byte, err error) {
	h := crypto.Keccak256Hash(msg)
	return crypto.Sign(h[:], privateKey)
}

func PrepareUnsignedTxnsWithFutureNonce(client *ethclient.Client, ccmp common.Address, nonceAddend uint64) (txns []TransactionWithSig, err error) {
	CCMPABI, err := eabi.JSON(strings.NewReader(abi.ICCMPABI))
	if err != nil {
		return nil, fmt.Errorf("fail to load abi: %s", err.Error())
	}
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("fail to get chainId: %s", err.Error())
	}
	from, err := GetOwner(client, ccmp)
	if err != nil {
		return nil, fmt.Errorf("fail to get owner of ccmp: %s", err.Error())
	}
	to := ccmp
	nonce, err := client.PendingNonceAt(context.Background(), from)
	if err != nil {
		return nil, fmt.Errorf("fail to get nonce: %s", err.Error())
	}
	nonce += nonceAddend
	value := big.NewInt(0)
	data, err := CCMPABI.Pack("pauseEthCrossChainManager")
	if err != nil {
		return nil, fmt.Errorf("fail to pack data: %s", err.Error())
	}
	msg := ethereum.CallMsg{From: from, To: &to, Value: value, Data: data}
	gasLimit, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return nil, fmt.Errorf("fail to estimate gas: %s", err.Error())
	}
	gasLimit = gasLimit * DefaultGasLimitMultiple / MultipleDecimal
	for i := 0; i < len(GasPriceList); i++ {
		gasPrice := big.NewInt(GasPriceList[i] * Gwei)
		tx := types.NewTransaction(nonce, to, value, gasLimit, gasPrice, data)
		rawTx, err := rlp.EncodeToBytes([]interface{}{
			tx.Nonce(),
			tx.GasPrice(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			chainId, uint(0), uint(0),
		})
		if err != nil {
			return nil, fmt.Errorf("fail to encode transaction: %s", err.Error())
		}
		signer := types.LatestSignerForChainID(chainId)
		h := signer.Hash(tx)
		txns = append(txns, TransactionWithSig{*tx, from.Hex(), common.Bytes2Hex(rawTx), h.Hex(), ""})
	}
	return txns, nil
}

func PrepareUnsignedTxns(client *ethclient.Client, ccmp common.Address) (txns []TransactionWithSig, err error) {
	CCMPABI, err := eabi.JSON(strings.NewReader(abi.ICCMPABI))
	if err != nil {
		return nil, fmt.Errorf("fail to load abi: %s", err.Error())
	}
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("fail to get chainId: %s", err.Error())
	}
	from, err := GetOwner(client, ccmp)
	if err != nil {
		return nil, fmt.Errorf("fail to get owner of ccmp: %s", err.Error())
	}
	to := ccmp
	nonce, err := client.PendingNonceAt(context.Background(), from)
	if err != nil {
		return nil, fmt.Errorf("fail to get nonce: %s", err.Error())
	}
	value := big.NewInt(0)
	data, err := CCMPABI.Pack("pauseEthCrossChainManager")
	if err != nil {
		return nil, fmt.Errorf("fail to pack data: %s", err.Error())
	}
	msg := ethereum.CallMsg{From: from, To: &to, Value: value, Data: data}
	gasLimit, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return nil, fmt.Errorf("fail to estimate gas: %s", err.Error())
	}
	gasLimit = gasLimit * DefaultGasLimitMultiple / MultipleDecimal
	for i := 0; i < len(GasPriceList); i++ {
		gasPrice := big.NewInt(GasPriceList[i] * Gwei)
		tx := types.NewTransaction(nonce, to, value, gasLimit, gasPrice, data)
		rawTx, err := rlp.EncodeToBytes([]interface{}{
			tx.Nonce(),
			tx.GasPrice(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			chainId, uint(0), uint(0),
		})
		if err != nil {
			return nil, fmt.Errorf("fail to encode transaction: %s", err.Error())
		}
		signer := types.LatestSignerForChainID(chainId)
		h := signer.Hash(tx)
		txns = append(txns, TransactionWithSig{*tx, from.Hex(), common.Bytes2Hex(rawTx), h.Hex(), ""})
	}
	return txns, nil
}

func PrepareUnsignedUnpauseTxns(client *ethclient.Client, ccmp common.Address) (txns []TransactionWithSig, err error) {
	CCMPABI, err := eabi.JSON(strings.NewReader(abi.ICCMPABI))
	if err != nil {
		return nil, fmt.Errorf("fail to load abi: %s", err.Error())
	}
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("fail to get chainId: %s", err.Error())
	}
	from, err := GetOwner(client, ccmp)
	if err != nil {
		return nil, fmt.Errorf("fail to get owner of ccmp: %s", err.Error())
	}
	to := ccmp
	nonce, err := client.PendingNonceAt(context.Background(), from)
	if err != nil {
		return nil, fmt.Errorf("fail to get nonce: %s", err.Error())
	}
	value := big.NewInt(0)
	data, err := CCMPABI.Pack("unpauseEthCrossChainManager")
	if err != nil {
		return nil, fmt.Errorf("fail to pack data: %s", err.Error())
	}
	msg := ethereum.CallMsg{From: from, To: &to, Value: value, Data: data}
	gasLimit, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return nil, fmt.Errorf("fail to estimate gas: %s", err.Error())
	}
	gasLimit = gasLimit * DefaultGasLimitMultiple / MultipleDecimal
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("makeAuth, get suggest gas price err: %v", err)
	}
	gasPrice.Mul(gasPrice, big.NewInt(2))
	tx := types.NewTransaction(nonce, to, value, gasLimit, gasPrice, data)
	rawTx, err := rlp.EncodeToBytes([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		chainId, uint(0), uint(0),
	})
	if err != nil {
		return nil, fmt.Errorf("fail to encode transaction: %s", err.Error())
	}
	signer := types.LatestSignerForChainID(chainId)
	h := signer.Hash(tx)
	txns = append(txns, TransactionWithSig{*tx, from.Hex(), common.Bytes2Hex(rawTx), h.Hex(), ""})
	return txns, nil
}

func PreparePauseTxns(client *ethclient.Client, ccmp common.Address, privateKey *ecdsa.PrivateKey) (txns []TransactionWithSig, err error) {
	CCMPABI, err := eabi.JSON(strings.NewReader(abi.ICCMPABI))
	if err != nil {
		return nil, fmt.Errorf("fail to load abi: %s", err.Error())
	}
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("fail to get chainId: %s", err.Error())
	}
	from := crypto.PubkeyToAddress(privateKey.PublicKey)
	to := ccmp
	nonce, err := client.PendingNonceAt(context.Background(), from)
	if err != nil {
		return nil, fmt.Errorf("fail to get nonce: %s", err.Error())
	}
	value := big.NewInt(0)
	data, err := CCMPABI.Pack("pauseEthCrossChainManager")
	if err != nil {
		return nil, fmt.Errorf("fail to pack data: %s", err.Error())
	}
	msg := ethereum.CallMsg{From: from, To: &to, Value: value, Data: data}
	gasLimit, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return nil, fmt.Errorf("fail to estimate gas: %s", err.Error())
	}
	gasLimit = gasLimit * DefaultGasLimitMultiple / MultipleDecimal
	for i := 0; i < len(GasPriceList); i++ {
		gasPrice := big.NewInt(GasPriceList[i] * Gwei)
		tx := types.NewTransaction(nonce, to, value, gasLimit, gasPrice, data)
		signer := types.LatestSignerForChainID(chainId)
		h := signer.Hash(tx)
		sig, err := crypto.Sign(h[:], privateKey)
		if err != nil {
			return nil, fmt.Errorf("fail to sign: %s", err.Error())
		}
		tx, err = tx.WithSignature(signer, sig)
		if err != nil {
			return nil, fmt.Errorf("fail to generate tx with signature: %s", err.Error())
		}
		rawTx, err := tx.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("fail to encode transaction: %s", err.Error())
		}
		txns = append(txns, TransactionWithSig{*tx, from.Hex(), common.Bytes2Hex(rawTx), h.Hex(), common.Bytes2Hex(sig)})
	}
	return txns, nil
}

func PrepareUnpauseTxns(client *ethclient.Client, ccmp common.Address, privateKey *ecdsa.PrivateKey) (txns []TransactionWithSig, err error) {
	CCMPABI, err := eabi.JSON(strings.NewReader(abi.ICCMPABI))
	if err != nil {
		return nil, fmt.Errorf("fail to load abi: %s", err.Error())
	}
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("fail to get chainId: %s", err.Error())
	}
	from := crypto.PubkeyToAddress(privateKey.PublicKey)
	to := ccmp
	nonce, err := client.PendingNonceAt(context.Background(), from)
	if err != nil {
		return nil, fmt.Errorf("fail to get nonce: %s", err.Error())
	}
	value := big.NewInt(0)
	data, err := CCMPABI.Pack("unpauseEthCrossChainManager")
	if err != nil {
		return nil, fmt.Errorf("fail to pack data: %s", err.Error())
	}
	msg := ethereum.CallMsg{From: from, To: &to, Value: value, Data: data}
	gasLimit, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		return nil, fmt.Errorf("fail to estimate gas: %s", err.Error())
	}
	gasLimit = gasLimit * DefaultGasLimitMultiple / MultipleDecimal
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("makeAuth, get suggest gas price err: %v", err)
	}
	gasPrice.Mul(gasPrice, big.NewInt(2))
	tx := types.NewTransaction(nonce, to, value, gasLimit, gasPrice, data)
	signer := types.LatestSignerForChainID(chainId)
	h := signer.Hash(tx)
	sig, err := crypto.Sign(h[:], privateKey)
	if err != nil {
		return nil, fmt.Errorf("fail to sign: %s", err.Error())
	}
	tx, err = tx.WithSignature(signer, sig)
	if err != nil {
		return nil, fmt.Errorf("fail to generate tx with signature: %s", err.Error())
	}
	rawTx, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("fail to encode transaction: %s", err.Error())
	}
	txns = append(txns, TransactionWithSig{*tx, from.Hex(), common.Bytes2Hex(rawTx), h.Hex(), common.Bytes2Hex(sig)})
	return txns, nil
}

func ExecutePauseTxns(client *ethclient.Client, txns []TransactionWithSig) error {
	suggestGasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return fmt.Errorf("fail to get suggest gasPrice: %s", err.Error())
	}
	suggestGasPrice.Mul(suggestGasPrice, big.NewInt(DefaultGasPriceMultiple))
	suggestGasPrice.Div(suggestGasPrice, big.NewInt(int64(MultipleDecimal)))
	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return fmt.Errorf("fail to get chainId: %s", err.Error())
	}
	signer := types.LatestSignerForChainID(chainId)
	for i := 0; i < len(txns); i++ {
		tx := &txns[i].Transaction
		if tx.GasPrice().Int64() < suggestGasPrice.Int64() {
			continue
		}
		sig := common.FromHex(txns[i].Sig)
		hash := common.FromHex(txns[i].Hash)
		sender := common.HexToAddress(txns[i].Sender)
		sig, err := SetV(hash, sig, sender)
		if err != nil {
			continue
		}
		tx, err = tx.WithSignature(signer, sig)
		if err != nil {
			return fmt.Errorf("fail to generate tx with signature: %s", err.Error())
		}
		err = client.SendTransaction(context.Background(), tx)
		if err != nil {
			return fmt.Errorf("fail to send transaction: %s", err.Error())
		}
		return WaitTxConfirm(client, tx.Hash(), "120s")
	}
	tx := &txns[len(txns)-1].Transaction
	fmt.Printf("SuggestGasPrice: %s . No suitable tx! Try to send tx with highest gasPrice: %s\n", suggestGasPrice.String(), tx.GasPrice().String())
	sig := common.FromHex(txns[len(txns)-1].Sig)
	hash := common.FromHex(txns[len(txns)-1].Hash)
	sender := common.HexToAddress(txns[len(txns)-1].Sender)
	sig, err = SetV(hash, sig, sender)
	if err != nil {
		return err
	}
	tx, err = tx.WithSignature(signer, sig)
	if err != nil {
		return fmt.Errorf("fail to generate tx with signature: %s", err.Error())
	}
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		return fmt.Errorf("fail to send transaction: %s", err.Error())
	}
	return WaitTxConfirm(client, tx.Hash(), "120s")
}

func GetOwner(client *ethclient.Client, contractAddress common.Address) (common.Address, error) {
	CCMPABI, err := eabi.JSON(strings.NewReader(abi.ICCMPABI))
	if err != nil {
		return ADDRESS_ZERO, fmt.Errorf("fail to load abi: %s", err.Error())
	}
	queryData, err := CCMPABI.Pack("owner")
	if err != nil {
		return ADDRESS_ZERO, fmt.Errorf("GetOwner() Error: fail to pack tx: %s", err.Error())
	}
	queryMsg := ethereum.CallMsg{To: &contractAddress, Data: queryData}
	res, err := client.CallContract(context.Background(), queryMsg, nil)
	if err != nil {
		return ADDRESS_ZERO, fmt.Errorf("GetOwner() Error: fail while CallContract: %s", err.Error())
	}
	result, err := CCMPABI.Unpack("owner", res)
	if err != nil {
		return ADDRESS_ZERO, fmt.Errorf("GetOwner() Error: fail to unpack result: %s", err.Error())
	}
	owner := result[0].(common.Address)
	return owner, nil
}

// Basic
func WaitTxConfirm(client *ethclient.Client, hash common.Hash, ddl string) error {
	ticker := time.NewTicker(time.Second * 1)
	timeOut, err := time.ParseDuration(ddl)
	if err != nil {
		timeOut = time.Second * 60
	}
	end := time.Now().Add(timeOut)
	for now := range ticker.C {
		_, pending, err := client.TransactionByHash(context.Background(), hash)
		if err != nil {
			if now.After(end) {
				return fmt.Errorf("failed to call TransactionByHash: %v", err)
			}
			continue
		}
		if !pending {
			break
		}
		if now.Before(end) {
			continue
		}
		return fmt.Errorf("Transaction pending for more than %s, check transaction %s on explorer yourself, make sure it's confirmed.", timeOut.String(), hash.Hex())
	}

	tx, err := client.TransactionReceipt(context.Background(), hash)
	if err != nil {
		return fmt.Errorf("faild to get receipt %s", hash.Hex())
	}

	if tx.Status == 0 {
		return fmt.Errorf("receipt failed %s", hash.Hex())
	}

	return nil
}

func SpeedUp(client *ethclient.Client, key *ecdsa.PrivateKey, hash common.Hash, newGasPrice *big.Int) error {
	tx, pending, err := client.TransactionByHash(context.Background(), hash)
	if err != nil {
		return fmt.Errorf("SpeedUp Error: %s", err.Error())
	}
	if !pending {
		return fmt.Errorf("SpeedUp Error: transaction %s has already been packaged", hash.Hex())
	}

	sender, err := GetSender(tx)
	if err != nil {
		return fmt.Errorf("SpeedUp Error: fail to get the sender of tx %s", hash.Hex())
	}
	authAddress := crypto.PubkeyToAddress(*key.Public().(*ecdsa.PublicKey))
	if sender != authAddress {
		return fmt.Errorf("SpeedUp Error: given key does not match the sender of transaction %s, given %s, want %s", hash.Hex(), authAddress, sender)
	}

	newTx := types.NewTransaction(tx.Nonce(), *tx.To(), tx.Value(), tx.Gas(), newGasPrice, tx.Data())
	signer := types.LatestSignerForChainID(tx.ChainId())
	newTx, err = types.SignTx(newTx, signer, key)
	err = client.SendTransaction(context.Background(), newTx)
	return WaitTxConfirm(client, newTx.Hash(), "120s")
}

func Cancel(client *ethclient.Client, key *ecdsa.PrivateKey, hash common.Hash, newGasPrice *big.Int) error {
	tx, pending, err := client.TransactionByHash(context.Background(), hash)
	if err != nil {
		return fmt.Errorf("Cancel Error: %s", err.Error())
	}
	if !pending {
		return fmt.Errorf("Cancel Error: transaction %s has already been packaged", hash.Hex())
	}

	sender, err := GetSender(tx)
	if err != nil {
		return fmt.Errorf("Cancel Error: fail to get the sender of tx %s", hash.Hex())
	}
	authAddress := crypto.PubkeyToAddress(*key.Public().(*ecdsa.PublicKey))
	if sender != authAddress {
		return fmt.Errorf("Cancel Error: given key does not match the sender of transaction %s, given %s, want %s", hash.Hex(), authAddress, sender)
	}

	newTx := types.NewTransaction(tx.Nonce(), authAddress, big.NewInt(0), 21000, newGasPrice, nil)
	signer := types.LatestSignerForChainID(tx.ChainId())
	newTx, err = types.SignTx(newTx, signer, key)
	err = client.SendTransaction(context.Background(), newTx)
	return WaitTxConfirm(client, newTx.Hash(), "120s")
}

func GetSender(tx *types.Transaction) (common.Address, error) {
	v, r, s := tx.RawSignatureValues()
	sig := append(r.Bytes(), s.Bytes()...)
	if len(v.Bytes()) == 0 {
		sig = append(sig, 0x00)
	} else {
		sig = append(sig, v.Bytes()...)
	}
	hash := types.LatestSignerForChainID(tx.ChainId()).Hash(tx)
	senderPub, err := crypto.SigToPub(hash.Bytes(), sig)
	return crypto.PubkeyToAddress(*senderPub), err
}

func SetV(hash, signature []byte, signer common.Address) ([]byte, error) {
	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid signature length")
	}
	signature[64] = 0
	pk, err := crypto.SigToPub(hash, signature)
	if err != nil || bytes.Compare(crypto.PubkeyToAddress(*pk).Bytes(), signer.Bytes()) != 0 {
		signature[64] = 1
		pk, err = crypto.SigToPub(hash, signature)
		if err != nil || bytes.Compare(crypto.PubkeyToAddress(*pk).Bytes(), signer.Bytes()) != 0 {
			return nil, fmt.Errorf("invalid signature")
		}
	}
	return signature, nil
}
