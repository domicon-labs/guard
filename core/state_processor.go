// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"math/big"
	"sync"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit() * 100)
	)
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	var (
		context = NewEVMBlockContext(header, p.bc, nil)
		vmenv   = vm.NewEVM(context, vm.TxContext{}, statedb, p.config, cfg)
		signer  = types.MakeSigner(p.config, header.Number, header.Time)
	)
	if !types.IsTxExtra(blockNumber) {
		// Iterate over and process the individual transactions
		for i, tx := range block.Transactions() {
			msg, err := TransactionToMessage(tx, signer, header.BaseFee)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			statedb.SetTxContext(tx.Hash(), i)
			receipt, err := applyTransaction(msg, p.config, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			receipts = append(receipts, receipt)
			allLogs = append(allLogs, receipt.Logs...)
			log.Info("Process", "hash", tx.Hash().Hex(), "receipts", receipt)
		}
	} else {
		//log.Info("new evm", "blockNumber", blockNumber.Uint64())
		transactions := block.Transactions()
		txChan := make(chan int, 2)

		var wg sync.WaitGroup
		wg.Add(len(transactions))
		interruptCh := make(chan struct{})
		for i := 0; i < 2; i++ {
			go func() {
				for {
					select {
					case txIndex := <-txChan:
						tx := transactions[txIndex]

						msg, err := TransactionToMessage(tx, signer, header.BaseFee)
						if err != nil {
							log.Error("TransactionToMessage", "blockNumber", blockNumber, "hash", tx.Hash().Hex(), "err", err)
							wg.Done()
							continue
						}

						// txExtra
						txExtra := types.ReadFileByHash(blockNumber, tx.Hash())
						if txExtra != nil {
							tx.TxExtra = txExtra

							txExtra.Origin = msg.From
							txExtra.GasPrice = msg.GasPrice
							// 验证状态树数据
							for addr, stobject := range txExtra.PreState {
								proof := txExtra.GetPreProof(addr)
								value, err := trie.VerifyProof(txExtra.PreStateRoot, crypto.Keccak256(addr.Bytes()), proof)
								if err != nil {
									log.Error("pre数据验证错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "address", addr, "root", txExtra.PreStateRoot, "key", crypto.Keccak256(addr.Bytes()), "proof", proof, "err", err)
									wg.Done()
									continue
								}
								bz, err := rlp.EncodeToBytes(&stobject)
								if err != nil {
									log.Error("pre数据转换错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "address", addr)
									wg.Done()
									continue
								}
								if len(value) != 0 && !bytes.Equal(bz, value) {
									log.Error("pre数据比对错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "address", addr, "value", value, "bz", bz)
									wg.Done()
									continue
								}
								//log.Info("Account", "hash", tx.Hash().Hex(), "addr", addr, "stobject", stobject)
							}

							for addr, bz := range txExtra.PostState {
								proof := txExtra.GetPostProof(addr)
								value, err := trie.VerifyProof(txExtra.PostStateRoot, crypto.Keccak256(addr.Bytes()), proof)
								if err != nil {
									log.Error("post数据验证错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "address", addr)
									wg.Done()
									continue
								}
								if !bytes.Equal(bz, value) {
									log.Error("post数据比对错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "address", addr)
									wg.Done()
									continue
								}
							}

							for addr, data := range txExtra.PreStorage {
								for hash, _ := range data {
									//log.Info("proof", "addr", addr, "data", txExtra.PreStorageProof[addr])
									proof := txExtra.GetPreStorageProof(addr, hash)
									root := txExtra.GetPreRootByAddress(addr)

									//log.Info("PreStorageInfo", "hash", txExtra.TxHash.Hex(), "addr", addr.Hex(), "hash", hash.Hex(),
									//	"val", c.Hex(), "proof", proof)
									if root == (common.Hash{}) || root == types.EmptyRootHash {
										continue
									}
									_, err := trie.VerifyProof(root, crypto.Keccak256(hash.Bytes()), proof)
									if err != nil {
										//log.Info("txExtra", "hash", tx.Hash().Hex(), "addr", addr, "key", hash.Hex(), "c", c, "value", value)

										log.Error("preStorage数据验证错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "address", addr, "root", root, "key", hash.Hex(), "proof", proof, "err", err)
										wg.Done()
										continue
									}
									//if !bytes.Equal(c.Bytes(), common.BytesToHash(value).Bytes()) {
									//	log.Info("string测试", "string(c)", string(c.Bytes()), "string(value)", string(common.BytesToHash(value).Bytes()))
									//	log.Error("preStorage数据比对错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "key", hash.Hex(), "c", c.Hex(), "value", value)
									//	wg.Done()
									//	continue
									//}
								}
							}

							for addr, data := range txExtra.PostStorage {
								for hash, _ := range data {
									proof := txExtra.GetPostStorageProof(addr, hash)
									root := txExtra.GetPostRootByAddress(addr)
									if root == types.EmptyRootHash {
										continue
									}
									_, err := trie.VerifyProof(root, crypto.Keccak256(hash.Bytes()), proof)
									if err != nil {
										log.Error("postStorage数据验证错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "address", addr)
										wg.Done()
										continue
									}
									//if !bytes.Equal(c.Bytes(), common.BytesToHash(value).Bytes()) {
									//	log.Error("postStorage数据比对错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "address", addr)
									//	wg.Done()
									//	continue
									//}
								}
							}

							for address, code := range txExtra.PreCode {
								codeHash := txExtra.GetPreCodeHashByAddress(address)
								if codeHash == nil || bytes.Equal(codeHash, types.EmptyCodeHash.Bytes()) {
									continue
								}
								if crypto.Keccak256Hash(code) != common.BytesToHash(codeHash) {
									if err != nil {
										log.Error("PreCode数据验证错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "address", address)
										wg.Done()
										continue
									}
								}
							}

							for address, code := range txExtra.PostCode {
								codeHash := txExtra.GetPostCodeHashByAddress(address)
								if bytes.Equal(codeHash, types.EmptyCodeHash.Bytes()) {
									continue
								}
								if crypto.Keccak256Hash(code) != common.BytesToHash(codeHash) {
									if err != nil {
										log.Error("PostCode数据验证错误", "blockNumber", blockNumber, "txHash", tx.Hash(), "address", address)
										wg.Done()
										continue
									}
								}
							}

							statedb.SetTxContext(tx.Hash(), txIndex)
							receipt, err := applyTransaction_new(txExtra, msg, p.config, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv)
							if err != nil {
								log.Error("applyTransaction_new", "blockNumber", blockNumber, "hash", tx.Hash().Hex(), "err", err)
								wg.Done()
								continue
							}
							tx.Receipt = receipt
							wg.Done()
						}

					case <-interruptCh:
						// If block precaching was interrupted, abort
						return
					}
				}
			}()
		}

		// it should be in a separate goroutine, to avoid blocking the critical path.
		for i := 0; i < len(transactions); i++ {
			select {
			case txChan <- i:
			case <-interruptCh:
				break
			}
		}
		wg.Wait()
		close(interruptCh)
		//pUseGas := new(uint64)
		for i, transaction := range block.Transactions() {
			if transaction.TxExtra != nil {
				txExtra := transaction.TxExtra
				//if txExtra.TxHash.String() == "0x6c929e1c3d860ee225d7f3a7addf9e3f740603d243260536dfa2f3cf02b51de4" {
				//	log.Info("测试中间根", "root", statedb.IntermediateRoot(p.config.IsEIP158(blockNumber)).Hex(),
				//		"txExtraRoot", txExtra.PreStateRoot.Hex())
				//}
				for address, enc := range txExtra.PostState {
					data := new(types.StateAccount)
					if err := rlp.DecodeBytes(enc, data); err != nil {
						if txExtra.MSuicide[address] == true {
							statedb.Suicide(address)
						}
						log.Error("PostState Failed to decode state object", "addr", address, "err", err)
						//statedb.CreateAccount(address)

						continue
					}
					temp := txExtra.PreState[address]
					//log.Info("数据对比", "addr", address.Hex(), "执行数据", temp, "预估数据", data)
					if data.Nonce != temp.Nonce {
						log.Error("Account Nonce Error", "hash", txExtra.TxHash.Hex(),
							"address", address,
							"执行数据", temp.Nonce,
							"预计数据", data.Nonce)
						//return nil, nil, 0, fmt.Errorf("Account Nonce Error")
					}

					if data.Balance.Cmp(temp.Balance) != 0 {
						log.Error("Account Balance Error", "hash", txExtra.TxHash.Hex(),
							"address", address,
							"执行数据", temp.Balance,
							"预计数据", data.Balance)
						//return nil, nil, 0, fmt.Errorf("Account Balance Error")
					}
					//log.Info("修改账户内容", "address", address.Hex(), "balance", data.Balance, "nonce", data.Nonce)
					statedb.SetBalance(address, data.Balance)
					statedb.SetNonce(address, data.Nonce)
				}
				//log.Info("PostState结束", "root", statedb.IntermediateRoot(p.config.IsEIP158(blockNumber)).Hex())
				for address, m := range txExtra.PostStorage {
					enc := txExtra.PostState[address]
					data := new(types.StateAccount)
					if err := rlp.DecodeBytes(enc, data); err != nil {
						log.Error("PostStorage Failed to decode state object", "addr", address, "err", err)
						//statedb.CreateAccount(address)
						continue
					}
					for hash, c := range m {
						temp := txExtra.PreStorage[address][hash]
						if temp != c {
							log.Error("执行交易Storage数据不一致", "hash", txExtra.TxHash.Hex(),
								"address", address, "hash", hash,
								"执行数据", temp.Hex(),
								"预计数据", c.Hex())
							//return nil, nil, 0, fmt.Errorf("执行交易账户数据不一致")
						}
						//log.Info("修改Storage", "addr", address.Hex(), "key", hash, "val", c)
						statedb.SetState(address, hash, temp)
					}
				}
				for address, i := range txExtra.PostCode {
					enc := txExtra.PostState[address]
					data := new(types.StateAccount)
					if err := rlp.DecodeBytes(enc, data); err != nil {
						log.Error("PostCode Failed to decode state object", "addr", address, "err", err)
						//statedb.CreateAccount(address)
						continue
					}
					//log.Info("修改code", "addr", address.Hex())
					statedb.SetCode(address, i)
				}

				statedb.SetTxContext(transaction.Hash(), i)
				for _, l := range txExtra.Logs() {
					if l != nil {
						statedb.AddLog(l)
					}
				}
				transaction.Receipt.Logs = statedb.GetLogs(transaction.Hash(), blockNumber.Uint64(), blockHash)
				transaction.Receipt.Bloom = types.CreateBloom(types.Receipts{transaction.Receipt})
			}
			if transaction.Receipt != nil {
				*usedGas += transaction.Receipt.GasUsed
				transaction.Receipt.CumulativeGasUsed = *usedGas
				receipts = append(receipts, transaction.Receipt)
				allLogs = append(allLogs, transaction.Receipt.Logs...)
			}
			if statedb.IntermediateRoot(p.bc.chainConfig.IsEIP158(block.Number())) != transaction.TxExtra.PostStateRoot {
				log.Info("transaction 后", "hash", transaction.Hash().Hex())
			}
		}
		//usedGas = pUseGas
	}

	// Fail if Shanghai not enabled and len(withdrawals) is non-zero.
	withdrawals := block.Withdrawals()
	if len(withdrawals) > 0 && !p.config.IsShanghai(block.Number(), block.Time()) {
		return nil, nil, 0, errors.New("withdrawals before shanghai")
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), withdrawals)
	if blockNumber.Uint64() == 246225 {
		root2 := statedb.IntermediateRoot_new(p.bc.chainConfig.IsEIP158(block.Number()))
		log.Info("查看Trie更改", "block", blockNumber, "header.root", block.Header().Root.Hex(), "root", root2.Hex())
	}
	//root2 := statedb.IntermediateRoot(p.bc.chainConfig.IsEIP158(block.Number()))
	//log.Info("最终性比对", "block", blockNumber, "header.root", block.Header().Root.Hex(), "root", root2.Hex())
	return receipts, allLogs, *usedGas, nil
}

func applyTransaction(msg *Message, config *params.ChainConfig, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())

	return receipt, err
}

func applyTransaction_new(txExtra *types.TxExtra, msg *Message, config *params.ChainConfig, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage_new(txExtra, evm, msg, gp)
	if err != nil {
		log.Error("ApplyMessage_new", "hash", tx.Hash().Hex(), "err", err)
		return nil, err
	}
	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		//root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
		root = txExtra.PostStateRoot.Bytes()
	}
	//atomic.AddUint64(usedGas, result.UsedGas)
	//log.Info("gas使用情况", "hash", tx.Hash(), "gas", result.UsedGas)
	//*usedGas += result.UsedGas
	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	//receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	//receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	return applyTransaction(msg, config, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}
