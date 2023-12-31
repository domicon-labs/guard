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
	"math/big"
	"sync"
	"time"
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
		time1 := time.Now()
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
		}
		time2 := time.Now()
		elapsedTime := time2.Sub(time1)
		log.Info("EVM", "blockNumber", blockNumber, "sum", elapsedTime)
	} else {
		//log.Info("new evm", "blockNumber", blockNumber.Uint64())
		time1 := time.Now()
		transactions := block.Transactions()

		file := types.ReadFile(blockNumber, len(block.Transactions()))
		time2 := time.Now()
		//log.Info("文件测试", "test", test)
		txChan := make(chan int, 10)

		var wg sync.WaitGroup
		wg.Add(len(transactions))
		interruptCh := make(chan struct{})
		for i := 0; i < 10; i++ {
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
						//txExtra := types.ReadFileByHash(blockNumber, tx.Hash())
						txExtra := file[tx.Hash()]
						if txExtra != nil {
							tx.TxExtra = txExtra

							txExtra.Origin = msg.From
							txExtra.GasPrice = msg.GasPrice

							statedb.SetTxContext(tx.Hash(), txIndex)
							receipt, err := applyTransaction_new(txExtra, msg, p.config, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv)
							if err != nil {
								log.Error("applyTransaction_new", "blockNumber", blockNumber, "hash", tx.Hash().Hex(), "err", err)
								wg.Done()
								continue
							}
							tx.Receipt = receipt
						}
						wg.Done()
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
		for i, transaction := range block.Transactions() {
			if transaction.TxExtra != nil {
				txExtra := transaction.TxExtra
				for address, sa := range txExtra.PreState {
					if txExtra.MSuicide[address] == true {
						statedb.Suicide(address)
						continue
					}
					//log.Info("preState", "address", address, "balance", sa.Balance, "Nonce", sa.Nonce)
					statedb.SetBalance(address, sa.Balance)
					statedb.SetNonce(address, sa.Nonce)
				}
				//log.Info("PostState结束", "root", statedb.IntermediateRoot(p.config.IsEIP158(blockNumber)).Hex())
				for address, m := range txExtra.PreStorage {
					if txExtra.PreState[address] == nil {
						continue
					}
					for hash, c := range m {
						//log.Info("preStoreage", "address", address, "key", hash, "val", c)
						statedb.SetState(address, hash, c)
					}
				}
				for address, code := range txExtra.PreCode {
					if code != nil && txExtra.PreState[address] != nil {
						//log.Info("PreCode", "address", address, "code", code)
						statedb.SetCode(address, code)
					}
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
		time3 := time.Now()
		log.Info("File", "blockNumber", blockNumber, "总时间", time3.Sub(time1), "读文件", time2.Sub(time1), "执行", time3.Sub(time2))
	}

	// Fail if Shanghai not enabled and len(withdrawals) is non-zero.
	withdrawals := block.Withdrawals()
	if len(withdrawals) > 0 && !p.config.IsShanghai(block.Number(), block.Time()) {
		return nil, nil, 0, errors.New("withdrawals before shanghai")
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), withdrawals)
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
