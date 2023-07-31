package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/emergency-button/config"
	"github.com/polynetwork/emergency-button/log"
	"github.com/polynetwork/emergency-button/shutTools"
)

var ADDRESS_ZERO common.Address = common.HexToAddress("0x0000000000000000000000000000000000000000")

type Msg struct {
	ChainId uint64
	Err     error
}

var inputFile string
var outputFile string
var confFile string
var pkconfFile string
var function string
var all bool

func init() {
	flag.StringVar(&inputFile, "i", "./txnsWithSig.json", "input txns file path")
	flag.StringVar(&outputFile, "o", "./rawTxns.json", "output txns file path")
	flag.StringVar(&confFile, "conf", "../ConfigJson/zionDevConfig.json", "configuration file path")
	flag.StringVar(&pkconfFile, "pkconf", "../PKConfig/PkConfig.json", "PrivateKey configuration file path")
	flag.BoolVar(&all, "all", false, "shut/restart all in config file")
	flag.StringVar(&function, "func", "", "choose function to run:\n"+
		"\n  generate raw txn:\n"+
		"  -func unpause -conf <./config.json>  -o <./rawTxns.json>  { -all | [chainId_0 chainId_1 chainId_2 ...] }\n"+
		"  -func futurePause -conf <./config.json>  -o <./rawTxns.json>  { -all | [chainId_0 chainId_1 chainId_2 ...] }\n"+
		"  -func pause -conf <./config.json>  -o <./rawTxns.json>  { -all | [chainId_0 chainId_1 chainId_2 ...] }\n"+
		"\n	 sign\n"+
		"  -func prepare -conf <./config.json>  -o <./txnsWithSig.json>  -pkconf <./pkconfig.json> { -all | [chainId_0 chainId_1 chainId_2 ...] }\n"+
		"\n	 execute\n"+
		"  -func execute -conf <./config.json>  -i <./txnsWithSig.json> { -all | [chainId_0 chainId_1 chainId_2 ...] }\n")
	flag.Parse()
}

func main() {
	switch function {
	case "unpause":
		log.Info("Processing...")

		conf, err := config.LoadConfig(confFile)
		if err != nil {
			log.Fatal("LoadConfig fail", err)
		}

		args := flag.Args()
		if all {
			args = conf.GetNetworkIds()
		}
		txns := shutTools.TxConfig{}
		for i := 0; i < len(args); i++ {
			id, err := strconv.Atoi(args[i])
			if err != nil {
				log.Errorf("can not parse arg %d : %s , %v", i, args[i], err)
				continue
			}

			netCfg := conf.GetNetwork(uint64(id))
			if netCfg == nil {
				log.Errorf("network with chainId %d not found in config file", id)
				continue
			}
			ccmpAddr := netCfg.EthCrossChainManagerProxy

			log.Infof("prepare %s ...", netCfg.Name)

			client, err := ethclient.Dial(netCfg.Provider)
			if err != nil {
				log.Errorf("fail to dial client %s of network %d", netCfg.Provider, id)
				continue
			}

			txList, err := shutTools.PrepareUnsignedUnpauseTxns(client, common.HexToAddress(ccmpAddr))
			if err != nil {
				log.Errorf("fail to prepare txns: %s", err.Error())
				continue
			}

			txns.Txns = append(txns.Txns, shutTools.TransactionList{PolyChainID: uint64(id), TxList: txList})

			err = writeTxConfig(txns, outputFile)
			if err != nil {
				log.Errorf("fail to write to file: %s: %s", outputFile, err.Error())
				continue
			}

			log.Infof("%s is prepared.", netCfg.Name)
		}
	case "future":
		log.Info("Processing...")

		conf, err := config.LoadConfig(confFile)
		if err != nil {
			log.Fatal("LoadConfig fail", err)
		}

		args := flag.Args()
		if all {
			args = conf.GetNetworkIds()
		}
		txns := shutTools.TxConfig{}
		for i := 0; i < len(args); i++ {
			id, err := strconv.Atoi(args[i])
			if err != nil {
				log.Errorf("can not parse arg %d : %s , %v", i, args[i], err)
				continue
			}

			netCfg := conf.GetNetwork(uint64(id))
			if netCfg == nil {
				log.Errorf("network with chainId %d not found in config file", id)
				continue
			}
			ccmpAddr := netCfg.EthCrossChainManagerProxy

			log.Infof("prepare %s ...", netCfg.Name)

			client, err := ethclient.Dial(netCfg.Provider)
			if err != nil {
				log.Errorf("fail to dial client %s of network %d", netCfg.Provider, id)
				continue
			}

			txList, err := shutTools.PrepareUnsignedTxnsWithFutureNonce(client, common.HexToAddress(ccmpAddr), 1)
			if err != nil {
				log.Errorf("fail to prepare txns: %s", err.Error())
				continue
			}

			txns.Txns = append(txns.Txns, shutTools.TransactionList{PolyChainID: uint64(id), TxList: txList})

			err = writeTxConfig(txns, outputFile)
			if err != nil {
				log.Errorf("fail to write to file: %s: %s", outputFile, err.Error())
				continue
			}

			log.Infof("%s is prepared.", netCfg.Name)
		}
	case "pause":
		log.Info("Processing...")

		conf, err := config.LoadConfig(confFile)
		if err != nil {
			log.Fatal("LoadConfig fail", err)
		}

		args := flag.Args()
		if all {
			args = conf.GetNetworkIds()
		}
		txns := shutTools.TxConfig{}
		for i := 0; i < len(args); i++ {
			id, err := strconv.Atoi(args[i])
			if err != nil {
				log.Errorf("can not parse arg %d : %s , %v", i, args[i], err)
				continue
			}

			netCfg := conf.GetNetwork(uint64(id))
			if netCfg == nil {
				log.Errorf("network with chainId %d not found in config file", id)
				continue
			}
			ccmpAddr := netCfg.EthCrossChainManagerProxy

			log.Infof("prepare %s ...", netCfg.Name)

			client, err := ethclient.Dial(netCfg.Provider)
			if err != nil {
				log.Errorf("fail to dial client %s of network %d", netCfg.Provider, id)
				continue
			}

			txList, err := shutTools.PrepareUnsignedTxns(client, common.HexToAddress(ccmpAddr))
			if err != nil {
				log.Errorf("fail to prepare txns: %s", err.Error())
				continue
			}

			txns.Txns = append(txns.Txns, shutTools.TransactionList{PolyChainID: uint64(id), TxList: txList})

			err = writeTxConfig(txns, outputFile)
			if err != nil {
				log.Errorf("fail to write to file: %s: %s", outputFile, err.Error())
				continue
			}

			log.Infof("%s is prepared.", netCfg.Name)
		}
	case "prepare":
		log.Info("Processing...")

		conf, err := config.LoadConfig(confFile)
		if err != nil {
			log.Fatal("LoadConfig fail", err)
		}

		PKconfig, err := config.LoadPrivateKeyConfig(pkconfFile)
		if err != nil {
			log.Fatal("LoadConfig fail", err)
		}

		args := flag.Args()
		if all {
			args = conf.GetNetworkIds()
		}
		txns := shutTools.TxConfig{}
		for i := 0; i < len(args); i++ {
			id, err := strconv.Atoi(args[i])
			if err != nil {
				log.Errorf("can not parse arg %d : %s , %v", i, args[i], err)
				continue
			}

			netCfg := conf.GetNetwork(uint64(id))
			if netCfg == nil {
				log.Errorf("network with chainId %d not found in config file", id)
				continue
			}
			ccmpAddr := netCfg.EthCrossChainManagerProxy

			log.Infof("prepare %s ...", netCfg.Name)
			pkCfg := PKconfig.GetSenderPrivateKey(netCfg.PrivateKeyNo)
			if pkCfg == nil {
				log.Errorf("privatekey with chainId %d not found in PKconfig file", netCfg.PrivateKeyNo)
			}
			err = pkCfg.PhraseCCMPrivateKey()
			if err != nil {
				log.Errorf("%v", err)
				continue
			}
			privateKey, err := crypto.HexToECDSA(pkCfg.CCMPOwnerPrivateKey)
			if err != nil {
				log.Errorf("%v", err)
				continue
			}

			client, err := ethclient.Dial(netCfg.Provider)
			if err != nil {
				log.Errorf("fail to dial client %s of network %d", netCfg.Provider, id)
				continue
			}

			txList, err := shutTools.PreparePauseTxns(client, common.HexToAddress(ccmpAddr), privateKey)
			if err != nil {
				log.Errorf("fail to prepare txns: %s", err.Error())
				continue
			}

			txns.Txns = append(txns.Txns, shutTools.TransactionList{PolyChainID: uint64(id), TxList: txList})

			err = writeTxConfig(txns, outputFile)
			if err != nil {
				log.Errorf("fail to write to file: %s: %s", outputFile, err.Error())
				continue
			}

			log.Infof("%s is prepared.", netCfg.Name)
		}
	case "execute":
		log.Info("Processing...")

		conf, err := config.LoadConfig(confFile)
		if err != nil {
			log.Fatal("LoadConfig fail", err)
		}

		txns, err := readTxConfig(inputFile)
		if err != nil {
			log.Fatal("LoadTxns fail", err)
		}

		args := flag.Args()
		if all {
			args = conf.GetNetworkIds()
		}
		if len(args) == 0 {
			log.Info("Done.")
			return
		}
		sig := make(chan Msg, 50)
		cnt := 0
		for i := 0; i < len(args); i++ {
			id, err := strconv.Atoi(args[i])
			if err != nil {
				log.Errorf("can not parse arg %d : %s , %v", i, args[i], err)
				continue
			}
			netCfg := conf.GetNetwork(uint64(id))
			if netCfg == nil {
				log.Errorf("network with chainId %d not found in config file", id)
				continue
			}
			txList := txns.GetTxns(uint64(id))
			if txList == nil {
				log.Errorf("txns with chainId %d not found in config file", id)
				continue
			}

			go func() {
				client, err := ethclient.Dial(netCfg.Provider)
				queueLens := len(netCfg.BackupProviders)
				for i := 0; err != nil; i = (i + 1) % queueLens {
					client, err = ethclient.Dial(netCfg.BackupProviders[i])
				}
				log.Infof("Shutting down %s ...", netCfg.Name)
				err = shutTools.ExecutePauseTxns(client, txList.TxList)
				for i := 0; err != nil; i = (i + 1) % queueLens {
					client, err = ethclient.Dial(netCfg.BackupProviders[i])
					if err != nil {
						continue
					}
					err = shutTools.ExecutePauseTxns(client, txList.TxList)
				}
				sig <- Msg{netCfg.PolyChainID, err}
			}()
			cnt += 1
		}
		for msg := range sig {
			cnt -= 1
			if msg.Err != nil {
				log.Errorf("chain %d error: %s", msg.ChainId, msg.Err)
			} else {
				log.Infof("CCM at chain %d has been shut down.", msg.ChainId)
			}
			if cnt == 0 {
				log.Info("Done.")
				break
			}
		}
	case "debug":
		log.Info("Processing...")

		conf, err := config.LoadConfig(confFile)
		if err != nil {
			log.Fatal("LoadConfig fail", err)
		}

		PKconfig, err := config.LoadPrivateKeyConfig(pkconfFile)
		if err != nil {
			log.Fatal("LoadConfig fail", err)
		}

		txns, err := readTxConfig(inputFile)
		if err != nil {
			log.Fatal("LoadTxns fail", err)
		}

		args := flag.Args()
		if all {
			args = conf.GetNetworkIds()
		}

		for i := 0; i < len(args); i++ {
			id, err := strconv.Atoi(args[i])
			if err != nil {
				log.Errorf("can not parse arg %d : %s , %v", i, args[i], err)
				continue
			}

			netCfg := conf.GetNetwork(uint64(id))
			if netCfg == nil {
				log.Errorf("network with chainId %d not found in config file", id)
				continue
			}

			log.Infof("prepare %s ...", netCfg.Name)
			pkCfg := PKconfig.GetSenderPrivateKey(netCfg.PrivateKeyNo)
			if pkCfg == nil {
				log.Errorf("privatekey with chainId %d not found in PKconfig file", netCfg.PrivateKeyNo)
			}
			err = pkCfg.PhraseCCMPrivateKey()
			if err != nil {
				log.Errorf("%v", err)
				continue
			}
			privateKey, err := crypto.HexToECDSA(pkCfg.CCMPOwnerPrivateKey)
			if err != nil {
				log.Errorf("%v", err)
				continue
			}

			tx := txns.GetTxns(uint64(id))
			raw := common.FromHex(tx.TxList[0].Raw)

			sig, err := shutTools.Sign(raw, privateKey)
			if err != nil {
				log.Errorf("fail to prepare txns: %s", err.Error())
				continue
			}
			fmt.Printf("sig: %x", sig)

			txns.Txns[0].TxList[0].Sig = common.Bytes2Hex(sig)
			writeTxConfig(txns, inputFile)
		}

	default:
		log.Errorf("unknown function", function)
	}

}

func readTxConfig(path string) (shutTools.TxConfig, error) {
	jsonBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return shutTools.TxConfig{}, fmt.Errorf("fail to load txns: " + err.Error())
	}

	res := shutTools.TxConfig{}
	err = json.Unmarshal(jsonBytes, &res)
	if err != nil {
		return shutTools.TxConfig{}, fmt.Errorf("fail to load txns: " + err.Error())
	}
	return res, nil
}

func writeTxConfig(txns shutTools.TxConfig, path string) error {
	res, err := json.MarshalIndent(&txns, "", "\t")
	if err != nil {
		return fmt.Errorf("fail to write txns to file: " + err.Error())
	}
	err = ioutil.WriteFile(path, res, 0777)
	if err != nil {
		return fmt.Errorf("fail to write txns to file: " + err.Error())
	}
	return nil
}
