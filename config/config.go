package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ssh/terminal"
)

var passwordCache string = ""

type Network struct {
	PolyChainID               uint64
	Name                      string
	Provider                  string
	BackupProviders           []string
	Wrapper                   string
	WrapperO3                 string
	NativeWrapper             string
	EthCrossChainManagerProxy string
	LockProxy                 string
	LockProxyPip4             string
	Swapper                   string
	PrivateKeyNo              uint64
}

type Config struct {
	Networks []Network
}

type PrivateKey struct {
	PrivateKeyNo                    uint64
	CCMPOwnerKeyStore               string
	CCMPOwnerPrivateKey             string
	LockProxyOwnerPrivateKey        string
	LockProxyOwnerKeyStore          string
	LockProxyPip4OwnerPrivateKey    string
	LockProxyPip4OwnerKeyStore      string
	SwapperOwnerPrivateKey          string
	SwapperOwnerKeyStore            string
	SwapperFeeCollectorPrivateKey   string
	SwapperFeeCollectorKeyStore     string
	WrapperFeeCollectorPrivateKey   string
	WrapperFeeCollectorKeyStore     string
	WrapperO3FeeCollectorPrivateKey string
	WrapperO3FeeCollectorKeyStore   string
	SenderPublicKey                 string
	SenderPrivateKey                string
}

type PkConfig struct {
	PrivateKeys []PrivateKey
}

type Token struct {
	PolyChainId uint64
	Address     common.Address
	LPAddress   common.Address
}

type TokenConfig struct {
	Name       string
	Symbol     string
	LPName     string
	LPSymbol   string
	Decimal    uint8
	InitSupply *big.Int
	Tokens     []Token
}

func LoadConfig(confFile string) (config *Config, err error) {
	jsonBytes, err := ioutil.ReadFile(confFile)
	if err != nil {
		return
	}

	config = &Config{}
	err = json.Unmarshal(jsonBytes, config)
	return
}

func (c *Config) GetNetwork(index uint64) (netConfig *Network) {
	for i := 0; i < len(c.Networks); i++ {
		if c.Networks[i].PolyChainID == index {
			return &c.Networks[i]
		}
	}
	return nil
}

func (c *Config) GetNetworkIds() []string {
	var res []string
	for i := 0; i < len(c.Networks); i++ {
		res = append(res, strconv.Itoa(int(c.Networks[i].PolyChainID)))
	}
	return res
}

func LoadPrivateKeyConfig(confFile string) (PKconfig *PkConfig, err error) {
	jsonBytes, err := ioutil.ReadFile(confFile)
	if err != nil {
		return
	}

	PKconfig = &PkConfig{}
	err = json.Unmarshal(jsonBytes, PKconfig)
	return
}

func (n *PkConfig) GetSenderPrivateKey(index uint64) (pkConfig *PrivateKey) {
	for i := 0; i < len(n.PrivateKeys); i++ {
		if n.PrivateKeys[i].PrivateKeyNo == index {
			return &n.PrivateKeys[i]
		}
	}
	return nil
}

func (n *PrivateKey) PhraseCCMPrivateKey() (err error) {
	_, hasPk1 := crypto.HexToECDSA(n.CCMPOwnerPrivateKey)
	hasCache1 := n.CCMPOwnerFromKeyStore(passwordCache)
	ok1 := hasPk1 == nil || hasCache1 == nil
	if !ok1 {
		if len(n.CCMPOwnerKeyStore) == 0 {
			return fmt.Errorf("Empty keystore")
		}
		fmt.Printf("Please type in password of %s: ", n.CCMPOwnerKeyStore)
		pass, err := terminal.ReadPassword(0)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
		fmt.Println()
		password := string(pass)
		password = strings.Replace(password, "\n", "", -1)
		passwordCache = password
		err = n.CCMPOwnerFromKeyStore(password)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
	}
	return nil
}

func (n *PrivateKey) PhraseLockProxyPrivateKey() (err error) {
	_, hasPk2 := crypto.HexToECDSA(n.LockProxyOwnerPrivateKey)
	hasCache2 := n.LockProxyOwnerFromKeyStore(passwordCache)
	ok2 := hasPk2 == nil || hasCache2 == nil
	if !ok2 { // need to recover LockProxy owner privatekey
		fmt.Printf("Please type in password of %s: ", n.LockProxyOwnerKeyStore)
		pass, err := terminal.ReadPassword(0)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
		fmt.Println()
		password := string(pass)
		password = strings.Replace(password, "\n", "", -1)
		passwordCache = password
		err = n.LockProxyOwnerFromKeyStore(password)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
	}
	return nil
}
func (n *PrivateKey) PhraseLockProxyPip4PrivateKey() (err error) {
	_, hasPk2 := crypto.HexToECDSA(n.LockProxyPip4OwnerPrivateKey)
	hasCache2 := n.LockProxyPip4OwnerFromKeyStore(passwordCache)
	ok2 := hasPk2 == nil || hasCache2 == nil
	if !ok2 { // need to recover LockProxy owner privatekey
		fmt.Printf("Please type in password of %s: ", n.LockProxyOwnerKeyStore)
		pass, err := terminal.ReadPassword(0)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
		fmt.Println()
		password := string(pass)
		password = strings.Replace(password, "\n", "", -1)
		passwordCache = password
		err = n.LockProxyPip4OwnerFromKeyStore(password)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
	}
	return nil
}

func (n *PrivateKey) PhraseSwapperPrivateKey() (err error) {
	_, hasPk3 := crypto.HexToECDSA(n.SwapperOwnerPrivateKey)
	hasCache3 := n.SwapperOwnerFromKeyStore(passwordCache)
	ok := hasPk3 == nil || hasCache3 == nil
	if !ok { // need to recover Swapper owner privatekey
		fmt.Printf("Please type in password of %s: ", n.SwapperOwnerKeyStore)
		pass, err := terminal.ReadPassword(0)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
		fmt.Println()
		password := string(pass)
		password = strings.Replace(password, "\n", "", -1)
		passwordCache = password
		err = n.SwapperOwnerFromKeyStore(password)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
	}
	return nil
}

func (n *PrivateKey) PhraseSwapperFeeCollectorPrivateKey() (err error) {
	_, hasPk4 := crypto.HexToECDSA(n.SwapperFeeCollectorPrivateKey)
	hasCache4 := n.SwapperFeeCollectorFromKeyStore(passwordCache)
	ok := hasPk4 == nil || hasCache4 == nil
	if !ok { // need to recover SwapperFeeCollector privatekey
		fmt.Printf("Please type in password of %s: ", n.SwapperFeeCollectorKeyStore)
		pass, err := terminal.ReadPassword(0)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
		fmt.Println()
		password := string(pass)
		password = strings.Replace(password, "\n", "", -1)
		passwordCache = password
		err = n.SwapperFeeCollectorFromKeyStore(password)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
	}
	return nil
}

func (n *PrivateKey) PhraseWrapperFeeCollectorPrivateKey() (err error) {
	_, hasPk5 := crypto.HexToECDSA(n.WrapperFeeCollectorPrivateKey)
	hasCache5 := n.WrapperFeeCollectorFromKeyStore(passwordCache)
	ok := hasPk5 == nil || hasCache5 == nil
	if !ok { // need to recover WrapperFeeCollector privatekey
		fmt.Printf("Please type in password of %s: ", n.WrapperFeeCollectorKeyStore)
		pass, err := terminal.ReadPassword(0)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
		fmt.Println()
		password := string(pass)
		password = strings.Replace(password, "\n", "", -1)
		passwordCache = password
		err = n.WrapperFeeCollectorFromKeyStore(password)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
	}
	return nil
}

func (n *PrivateKey) PhraseWrapperO3FeeCollectorPrivateKey() (err error) {
	_, hasPk6 := crypto.HexToECDSA(n.WrapperO3FeeCollectorPrivateKey)
	hasCache6 := n.WrapperO3FeeCollectorFromKeyStore(passwordCache)
	ok := hasPk6 == nil || hasCache6 == nil
	if !ok { // need to recover WrapperFeeCollector privatekey
		fmt.Printf("Please type in password of %s: ", n.WrapperO3FeeCollectorKeyStore)
		pass, err := terminal.ReadPassword(0)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
		fmt.Println()
		password := string(pass)
		password = strings.Replace(password, "\n", "", -1)
		passwordCache = password
		err = n.WrapperO3FeeCollectorFromKeyStore(password)
		if err != nil {
			return fmt.Errorf("fail to phrase private key, %v", err)
		}
	}
	return nil
}

func (n *PrivateKey) CCMPOwnerFromKeyStore(pswd string) (err error) {
	ks1, err := ioutil.ReadFile(n.CCMPOwnerKeyStore)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	key1, err := keystore.DecryptKey(ks1, pswd)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	n.CCMPOwnerPrivateKey = fmt.Sprintf("%x", crypto.FromECDSA(key1.PrivateKey))
	return nil
}

func (n *PrivateKey) LockProxyOwnerFromKeyStore(pswd string) (err error) {
	ks2, err := ioutil.ReadFile(n.LockProxyOwnerKeyStore)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	key2, err := keystore.DecryptKey(ks2, pswd)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	n.LockProxyOwnerPrivateKey = fmt.Sprintf("%x", crypto.FromECDSA(key2.PrivateKey))
	return nil
}

func (n *PrivateKey) LockProxyPip4OwnerFromKeyStore(pswd string) (err error) {
	ks2, err := ioutil.ReadFile(n.LockProxyPip4OwnerKeyStore)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	key2, err := keystore.DecryptKey(ks2, pswd)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	n.LockProxyPip4OwnerPrivateKey = fmt.Sprintf("%x", crypto.FromECDSA(key2.PrivateKey))
	return nil
}

func (n *PrivateKey) SwapperOwnerFromKeyStore(pswd string) (err error) {
	ks3, err := ioutil.ReadFile(n.SwapperOwnerKeyStore)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	key3, err := keystore.DecryptKey(ks3, pswd)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	n.SwapperOwnerPrivateKey = fmt.Sprintf("%x", crypto.FromECDSA(key3.PrivateKey))
	return nil
}

func (n *PrivateKey) SwapperFeeCollectorFromKeyStore(pswd string) (err error) {
	ks4, err := ioutil.ReadFile(n.SwapperFeeCollectorKeyStore)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	key4, err := keystore.DecryptKey(ks4, pswd)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	n.SwapperFeeCollectorPrivateKey = fmt.Sprintf("%x", crypto.FromECDSA(key4.PrivateKey))
	return nil
}

func (n *PrivateKey) WrapperFeeCollectorFromKeyStore(pswd string) (err error) {
	ks5, err := ioutil.ReadFile(n.WrapperFeeCollectorKeyStore)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	key5, err := keystore.DecryptKey(ks5, pswd)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	n.WrapperFeeCollectorPrivateKey = fmt.Sprintf("%x", crypto.FromECDSA(key5.PrivateKey))
	return nil
}

func (n *PrivateKey) WrapperO3FeeCollectorFromKeyStore(pswd string) (err error) {
	ks6, err := ioutil.ReadFile(n.WrapperO3FeeCollectorKeyStore)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	key6, err := keystore.DecryptKey(ks6, pswd)
	if err != nil {
		return fmt.Errorf("fail to recover private key from keystore file, %v", err)
	}
	n.WrapperO3FeeCollectorPrivateKey = fmt.Sprintf("%x", crypto.FromECDSA(key6.PrivateKey))
	return nil
}

func LoadToken(tokenFile string) (tokens *TokenConfig, err error) {
	jsonBytes, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return
	}

	tokens = &TokenConfig{}
	err = json.Unmarshal(jsonBytes, tokens)
	return
}

func (c *TokenConfig) GetToken(index uint64) (netConfig *Token) {
	for i := 0; i < len(c.Tokens); i++ {
		if c.Tokens[i].PolyChainId == index {
			return &c.Tokens[i]
		}
	}
	return nil
}

func (c *TokenConfig) GetTokenIds() []string {
	var res []string
	for i := 0; i < len(c.Tokens); i++ {
		res = append(res, strconv.Itoa(int(c.Tokens[i].PolyChainId)))
	}
	return res
}
