package types

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	"os"
	"strings"
)

var (
	// emptyRoot is the known root hash of an empty trie.
	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	emptyAddr     = crypto.Keccak256Hash(common.Address{}.Bytes())
	emptyCodeHash = crypto.Keccak256(nil)
)

type TxExtra struct {
	TxHash        common.Hash
	PreStateRoot  common.Hash
	PostStateRoot common.Hash

	PreState  map[common.Address]*StateAccount
	PostState map[common.Address][]byte

	PreStorage  map[common.Address]map[common.Hash]common.Hash
	PostStorage map[common.Address]map[common.Hash]common.Hash

	PreStateProof  map[common.Address][][]byte
	PostStateProof map[common.Address][][]byte

	PreStorageProof  map[common.Address]map[common.Hash][][]byte
	PostStorageProof map[common.Address]map[common.Hash][][]byte

	PreCode  map[common.Address][]byte
	PostCode map[common.Address][]byte

	Refund   uint64
	MSuicide map[common.Address]bool

	logs map[common.Hash][]*Log

	Hasher    crypto.KeccakState
	HasherBuf common.Hash

	Origin   common.Address
	GasPrice *big.Int

	CallGasTemp uint64
}

func NewTxExtra(hash common.Hash) *TxExtra {
	return &TxExtra{
		TxHash:           hash,
		PreStateRoot:     common.Hash{},
		PostStateRoot:    common.Hash{},
		PreState:         map[common.Address]*StateAccount{},
		PostState:        map[common.Address][]byte{},
		PreStorage:       map[common.Address]map[common.Hash]common.Hash{},
		PostStorage:      map[common.Address]map[common.Hash]common.Hash{},
		PreStateProof:    map[common.Address][][]byte{},
		PostStateProof:   map[common.Address][][]byte{},
		PreStorageProof:  map[common.Address]map[common.Hash][][]byte{},
		PostStorageProof: map[common.Address]map[common.Hash][][]byte{},
		PreCode:          map[common.Address][]byte{},
		PostCode:         map[common.Address][]byte{},
		Refund:           0,
		MSuicide:         map[common.Address]bool{},
		logs:             map[common.Hash][]*Log{},
		Origin:           common.Address{},
		GasPrice:         new(big.Int).SetUint64(0),
	}
}

func (t *TxExtra) Copy() *TxExtra {
	cpy := &TxExtra{
		TxHash:           t.TxHash,
		PreStateRoot:     t.PreStateRoot,
		PostStateRoot:    t.PostStateRoot,
		PreState:         make(map[common.Address]*StateAccount),
		PostState:        make(map[common.Address][]byte),
		PreStorage:       make(map[common.Address]map[common.Hash]common.Hash),
		PostStorage:      make(map[common.Address]map[common.Hash]common.Hash),
		PreStateProof:    make(map[common.Address][][]byte),
		PostStateProof:   make(map[common.Address][][]byte),
		PreStorageProof:  make(map[common.Address]map[common.Hash][][]byte),
		PostStorageProof: make(map[common.Address]map[common.Hash][][]byte),
		PreCode:          make(map[common.Address][]byte),
		PostCode:         make(map[common.Address][]byte),
		Refund:           t.Refund,
		MSuicide:         make(map[common.Address]bool),
		logs:             make(map[common.Hash][]*Log),
	}
	for address, account := range t.PreState {
		cpy.PreState[address] = &StateAccount{
			Nonce:    account.Nonce,
			Balance:  account.Balance,
			Root:     account.Root,
			CodeHash: account.CodeHash,
		}
	}
	for address, bytes := range t.PostState {
		cpy.PostState[address] = bytes
	}
	for address, m := range t.PreStorage {
		cpy.PreStorage[address] = make(map[common.Hash]common.Hash)
		for hash, c := range m {
			cpy.PreStorage[address][hash] = c
		}
	}

	for address, m := range t.PostStorage {
		cpy.PostStorage[address] = make(map[common.Hash]common.Hash)
		for hash, c := range m {
			cpy.PostStorage[address][hash] = c
		}
	}

	for address, i := range t.PreStateProof {
		cpy.PreStateProof[address] = i
	}
	for address, i := range t.PostStateProof {
		cpy.PostStateProof[address] = i
	}

	for address, m := range t.PreStorageProof {
		cpy.PreStorageProof[address] = make(map[common.Hash][][]byte)
		for hash, i := range m {
			cpy.PreStorageProof[address][hash] = i
		}
	}

	for address, m := range t.PostStorageProof {
		cpy.PostStorageProof[address] = make(map[common.Hash][][]byte)
		for hash, i := range m {
			cpy.PostStorageProof[address][hash] = i
		}
	}

	for address, bytes := range t.PreCode {
		cpy.PreCode[address] = bytes
	}

	for address, bytes := range t.PostCode {
		cpy.PostCode[address] = bytes
	}

	for address, b := range t.MSuicide {
		cpy.MSuicide[address] = b
	}

	for hash, logs := range t.logs {
		cpy.logs[hash] = make([]*Log, len(logs))
		for _, l := range logs {
			cpy.logs[hash] = append(cpy.logs[hash], l)
		}
	}
	cpy.Origin = t.Origin
	return cpy
}

func (t *TxExtra) Revert(snap *TxExtra) {
	t.logs = make(map[common.Hash][]*Log)
	t.Origin = snap.Origin
	t.Refund = snap.Refund
	t.PreState = make(map[common.Address]*StateAccount)

	for address, account := range snap.PreState {
		t.PreState[address] = &StateAccount{
			Nonce:    account.Nonce,
			Balance:  account.Balance,
			Root:     account.Root,
			CodeHash: account.CodeHash,
		}
	}
	for address, bytes := range snap.PostState {
		t.PostState[address] = bytes
	}
	for address, m := range snap.PreStorage {
		t.PreStorage[address] = make(map[common.Hash]common.Hash)
		for hash, c := range m {
			t.PreStorage[address][hash] = c
		}
	}

	for address, m := range snap.PostStorage {
		t.PostStorage[address] = make(map[common.Hash]common.Hash)
		for hash, c := range m {
			t.PostStorage[address][hash] = c
		}
	}

	for address, i := range snap.PreStateProof {
		t.PreStateProof[address] = i
	}
	for address, i := range snap.PostStateProof {
		t.PostStateProof[address] = i
	}

	for address, m := range snap.PreStorageProof {
		t.PreStorageProof[address] = make(map[common.Hash][][]byte)
		for hash, i := range m {
			t.PreStorageProof[address][hash] = i
		}
	}

	for address, m := range snap.PostStorageProof {
		t.PostStorageProof[address] = make(map[common.Hash][][]byte)
		for hash, i := range m {
			t.PostStorageProof[address][hash] = i
		}
	}

	for address, bytes := range snap.PreCode {
		t.PreCode[address] = bytes
	}

	for address, bytes := range snap.PostCode {
		t.PostCode[address] = bytes
	}

	for address, b := range snap.MSuicide {
		t.MSuicide[address] = b
	}
	for hash, logs := range snap.logs {
		t.logs[hash] = make([]*Log, len(logs))
		for _, l := range logs {
			t.logs[hash] = append(t.logs[hash], l)
		}
	}
}

func (t *TxExtra) AddPreState(address common.Address, stateAccount *StateAccount) {
	if t.PreState == nil {
		t.PreState = map[common.Address]*StateAccount{}
	}
	t.PreState[address] = stateAccount
}

func (t *TxExtra) AddPostState(address common.Address, enc []byte) {
	if t.PostState == nil {
		t.PostState = map[common.Address][]byte{}
	}
	t.PostState[address] = enc
}

func (t *TxExtra) AddPreStorage(address common.Address, key, value common.Hash) {
	if t.PreStorage[address] == nil {
		t.PreStorage[address] = map[common.Hash]common.Hash{}
	}
	t.PreStorage[address][key] = value
}

func (t *TxExtra) AddPostStorage(address common.Address, key, value common.Hash) {
	if t.PostStorage[address] == nil {
		t.PostStorage[address] = map[common.Hash]common.Hash{}
	}
	t.PostStorage[address][key] = value
}

func (t *TxExtra) AddPreStateProof(address common.Address, proof [][]byte) {
	t.PreStateProof[address] = proof
}

func (t *TxExtra) AddPostStateProof(address common.Address, proof [][]byte) {
	t.PostStateProof[address] = proof
}

func (t *TxExtra) AddPreStorageProof(address common.Address, key common.Hash, proof [][]byte) {
	if t.PreStorageProof[address] == nil {
		t.PreStorageProof[address] = map[common.Hash][][]byte{}
	}
	t.PreStorageProof[address][key] = proof
}

func (t *TxExtra) AddPostStorageProof(address common.Address, key common.Hash, proof [][]byte) {
	if t.PostStorageProof[address] == nil {
		t.PostStorageProof[address] = map[common.Hash][][]byte{}
	}
	t.PostStorageProof[address][key] = proof
}

func (t *TxExtra) AddPreCode(address common.Address, enc []byte) {
	if t.PreCode == nil {
		t.PreCode = map[common.Address][]byte{}
	}
	t.PreCode[address] = enc
}
func (t *TxExtra) AddPostCode(address common.Address, enc []byte) {
	if t.PostCode == nil {
		t.PostCode = map[common.Address][]byte{}
	}
	t.PostCode[address] = enc
}

func (t *TxExtra) GetPreProof(address common.Address) *ExtraProof {
	p := t.PreStateProof[address]
	if p != nil {
		return NewExtraProof(p)
	}
	return nil
}
func (t *TxExtra) GetPostProof(address common.Address) *ExtraProof {
	p := t.PostStateProof[address]
	if p != nil {
		return NewExtraProof(p)
	}
	return nil
}
func (t *TxExtra) GetPreStorageProof(address common.Address, hash common.Hash) *ExtraProof {
	p := t.PreStorageProof[address][hash]
	if p != nil {
		return NewExtraProof(p)
	}
	return nil
}
func (t *TxExtra) GetPostStorageProof(address common.Address, hash common.Hash) *ExtraProof {
	p := t.PostStorageProof[address][hash]
	if p != nil {
		return NewExtraProof(p)
	}
	return nil
}

func (t *TxExtra) GetPreRootByAddress(address common.Address) common.Hash {
	//log.Info("测试", "hash", t.TxHash.Hex(), "address", address, "prestate", t.PreState[address])
	s := t.PreState[address]
	if s != nil {
		return s.Root
	}
	return common.Hash{}
}

func (t *TxExtra) GetPostRootByAddress(address common.Address) common.Hash {
	enc := t.PostState[address]
	data := new(StateAccount)
	if err := rlp.DecodeBytes(enc, data); err != nil {
		//log.Error("GetPostRootByAddress Failed to decode state object", "addr", address, "err", err)
		return EmptyRootHash
	}
	return data.Root
}

func (t *TxExtra) GetPreCodeHashByAddress(address common.Address) []byte {
	//log.Info("测试", "hash", t.TxHash.Hex(), "address", address, "prestate", t.PreState[address])
	s := t.PreState[address]
	if s != nil {
		return s.CodeHash
	}
	return nil
}

func (t *TxExtra) GetPostCodeHashByAddress(address common.Address) []byte {
	enc := t.PostState[address]
	data := new(StateAccount)
	if err := rlp.DecodeBytes(enc, data); err != nil {
		log.Error("GetPostCodeHashByAddress Failed to decode state object", "addr", address, "err", err)
		return emptyCodeHash
	}
	return data.CodeHash
}

func (t *TxExtra) Suicide(address common.Address) bool {
	t.MSuicide[address] = true
	return true
}

func (t *TxExtra) HasSuicided(address common.Address) bool {
	return t.MSuicide[address]
}

func (t *TxExtra) GetNonce(address common.Address) uint64 {
	if t.PreState[address] != nil {
		return t.PreState[address].Nonce
	}
	return 0
}

func (t *TxExtra) AddRefund(gas uint64) {
	t.Refund += gas
}
func (t *TxExtra) SubRefund(gas uint64) {
	t.Refund -= gas
}

func (t *TxExtra) GetRefund() uint64 {
	return t.Refund
}
func (t *TxExtra) SetRefund(gas uint64) {
	t.Refund = gas
}

func (t *TxExtra) SetNonce(address common.Address, nonce uint64) {
	if t.PreState[address].Balance != nil {
		t.PreState[address].Nonce = nonce
	} else {
		t.PreState[address] = &StateAccount{
			Nonce:    nonce,
			Balance:  nil,
			Root:     common.Hash{},
			CodeHash: nil,
		}
	}
}

func (t *TxExtra) GetCode(address common.Address) []byte {
	return t.PreCode[address]
}

func (t *TxExtra) GetCodeHash(address common.Address) common.Hash {
	acc := t.PreState[address]
	if acc != nil {
		return common.BytesToHash(acc.CodeHash)
	}
	return EmptyCodeHash
}

func (t *TxExtra) SetCode(address common.Address, code []byte) {
	t.PreState[address].CodeHash = crypto.Keccak256Hash(code).Bytes()
	t.PreCode[address] = code
}

func (t *TxExtra) Transfer(sender, recipient common.Address, amount *big.Int) {
	//log.Info("Transfer", "hash", t.TxHash, "sender", sender.Hex(), "recipient", recipient.Hex(), "amount", amount)
	s := t.PreState[sender]
	s.Balance = new(big.Int).Sub(s.Balance, amount)
	r := t.PreState[recipient]
	r.Balance = new(big.Int).Add(r.Balance, amount)
}

func (t *TxExtra) GetState(address common.Address, key common.Hash) common.Hash {
	s := t.PreStorage[address]
	if s == nil {
		return common.Hash{}
	}
	return t.PreStorage[address][key]
}

func (t *TxExtra) SetState(address common.Address, key, val common.Hash) {
	s := t.PreStorage[address]
	if s == nil {
		s = map[common.Hash]common.Hash{}
	}
	s[key] = val
}

func (t *TxExtra) GetBalance(address common.Address) *big.Int {
	s := t.PreState[address]
	if s != nil {
		return s.Balance
	}
	return common.Big0
}

func (t *TxExtra) SubBalance(address common.Address, amout *big.Int) {
	s := t.PreState[address]
	if s != nil {
		s.Balance = new(big.Int).Sub(s.Balance, amout)
	}
}

func (t *TxExtra) AddBalance(address common.Address, amout *big.Int) {
	s := t.PreState[address]
	if s != nil {
		s.Balance = new(big.Int).Add(s.Balance, amout)
	}
}

func (t *TxExtra) CanTransfer(address common.Address, amount *big.Int) bool {
	return t.GetBalance(address).Cmp(amount) >= 0
}

func (t *TxExtra) Exist(address common.Address) bool {
	if t.PreState[address] != nil {
		return true
	}
	return false
}

func (t *TxExtra) Empty(address common.Address) bool {
	s := t.PreState[address]
	return s == nil || (s.Nonce == 0 && s.Balance.Sign() == 0 && bytes.Equal(s.CodeHash, EmptyCodeHash.Bytes()))
}

func (t *TxExtra) CreateAccount(address common.Address) {
	s := t.PreState[address]
	if s == nil {
		t.AddPreState(address, &StateAccount{
			Nonce:    0,
			Balance:  new(big.Int),
			Root:     emptyRoot,
			CodeHash: emptyCodeHash,
		})
	}
}

func (t *TxExtra) AddLog(log *Log) {
	t.logs[t.TxHash] = append(t.logs[t.TxHash], log)
}

// GetLogs returns the logs matching the specified transaction hash, and annotates
// them with the given blockNumber and blockHash.
func (t *TxExtra) GetLogs(hash common.Hash, blockNumber uint64, blockHash common.Hash) []*Log {
	logs := t.logs[hash]
	for _, l := range logs {
		l.BlockNumber = blockNumber
		l.BlockHash = blockHash
	}
	return logs
}

func (t *TxExtra) Logs() []*Log {
	var logs []*Log
	for _, lgs := range t.logs {
		logs = append(logs, lgs...)
	}
	return logs
}

func IsTxExtra(blockNumber *big.Int) bool {
	left := new(big.Int).Quo(blockNumber, new(big.Int).SetInt64(1000))
	fileInfo, err := os.Stat("/Users/yulin/eth/execution/pioneer/build/bin/minerExtra/" + left.String() + "/" + blockNumber.String() + ".txt")
	if os.IsNotExist(err) {
		//log.Info("IsTxExtra", "err", err)
		return false
	}
	if fileInfo.Size() == 0 {
		log.Info("size0")
		return false
	}
	return true
}

func ReadFile(blockNumber *big.Int, count int) map[common.Hash]*TxExtra {
	left := new(big.Int).Quo(blockNumber, new(big.Int).SetInt64(1000))
	myfile, err := os.Open("/Users/yulin/eth/execution/pioneer/build/bin/minerExtra/" + left.String() + "/" + blockNumber.String() + ".txt") //open the file
	if err != nil {
		log.Error("ReadFile", "Error opening file:", err)
		return nil
	}
	defer myfile.Close()
	scanner := bufio.NewScanner(myfile)
	start := false
	re := make(map[common.Hash]*TxExtra, count)

	var tempTxExtra *TxExtra
	for scanner.Scan() {
		line := scanner.Text()
		lArr := strings.Split(line, "\t")
		stype := lArr[0]

		if start {
			if stype == "txHash" {
				start = false
				re[tempTxExtra.TxHash] = tempTxExtra
				continue
			}
			switch stype {
			case "preStateRoot":
				tempTxExtra.PreStateRoot = common.HexToHash(lArr[1])
			case "postStateRoot":
				tempTxExtra.PostStateRoot = common.HexToHash(lArr[1])
			case "code":
				//if c, err := base64.StdEncoding.DecodeString(lArr[2]); err == nil {
				//	txExtra.AddCode(common.HexToAddress(lArr[1]), c)
				//}
			case "preState":
				if enc, err := base64.StdEncoding.DecodeString(lArr[2]); err == nil {
					data := new(StateAccount)
					if err := rlp.DecodeBytes(enc, data); err != nil {
						//txExtra.AddPreState(common.HexToAddress(lArr[1]), &StateAccount{
						//	Nonce:    0,
						//	Balance:  new(big.Int),
						//	Root:     emptyRoot,
						//	CodeHash: emptyCodeHash,
						//})
						//log.Error("ReadFileByHash Failed to decode state object", "addr", common.HexToAddress(lArr[1]), "err", err)
					} else {
						tempTxExtra.AddPreState(common.HexToAddress(lArr[1]), data)
					}
				}
			case "postState":
				if c, err := base64.StdEncoding.DecodeString(lArr[2]); err == nil {
					tempTxExtra.AddPostState(common.HexToAddress(lArr[1]), c)
				}
			case "preStateProof":
				var path [][]byte
				for _, s := range lArr[2:] {
					if c, err := base64.StdEncoding.DecodeString(s); err == nil {
						path = append(path, c)
					}
				}
				tempTxExtra.AddPreStateProof(common.HexToAddress(lArr[1]), path)
			case "postStateProof":
				var path [][]byte
				for _, s := range lArr[2:] {
					if c, err := base64.StdEncoding.DecodeString(s); err == nil {
						path = append(path, c)
					}
				}
				tempTxExtra.AddPostStateProof(common.HexToAddress(lArr[1]), path)
			case "preStorage":
				//log.Info("preStorage", "address", lArr[1], "hash", lArr[2], "val", lArr[3])
				tempTxExtra.AddPreStorage(common.HexToAddress(lArr[1]), common.HexToHash(lArr[2]), common.HexToHash(lArr[3]))
				//log.Info("preStorage", "extra.PreStorage", extraData.PreStorageData.List)
			case "postStorage":
				//log.Info("postStorage", "address", lArr[1], "hash", lArr[2], "val", lArr[3])
				tempTxExtra.AddPostStorage(common.HexToAddress(lArr[1]), common.HexToHash(lArr[2]), common.HexToHash(lArr[3]))
			case "preStorageProof":
				var path [][]byte
				for _, s := range lArr[3:] {
					if c, err := base64.StdEncoding.DecodeString(s); err == nil {
						path = append(path, c)
					}
				}
				tempTxExtra.AddPreStorageProof(common.HexToAddress(lArr[1]), common.HexToHash(lArr[2]), path)
			case "postStorageProof":
				var path [][]byte
				for _, s := range lArr[3:] {
					if c, err := base64.StdEncoding.DecodeString(s); err == nil {
						path = append(path, c)
					}
				}
				tempTxExtra.AddPostStorageProof(common.HexToAddress(lArr[1]), common.HexToHash(lArr[2]), path)

			case "preCode":
				if c, err := base64.StdEncoding.DecodeString(lArr[2]); err == nil {
					tempTxExtra.AddPreCode(common.HexToAddress(lArr[1]), c)
				}
			case "postCode":
				if c, err := base64.StdEncoding.DecodeString(lArr[2]); err == nil {
					tempTxExtra.AddPostCode(common.HexToAddress(lArr[1]), c)
				}
			default:
			}
		}
		if stype == "txHash" {
			tempTxExtra = NewTxExtra(common.HexToHash(lArr[1]))
			start = true
		}
	}
	return re
}

func ReadFileByHash(blockNumber *big.Int, hash common.Hash) *TxExtra {
	left := new(big.Int).Quo(blockNumber, new(big.Int).SetInt64(1000))
	myfile, err := os.Open("/Users/yulin/eth/execution/pioneer/build/bin/minerExtra/" + left.String() + "/" + blockNumber.String() + ".txt") //open the file
	if err != nil {
		log.Info("Test", "Error opening file:", err)
		return nil
	}
	defer myfile.Close()
	scanner := bufio.NewScanner(myfile) //scan the contents of a file and print line by line
	start := false
	txExtra := NewTxExtra(hash)
	for scanner.Scan() {
		line := scanner.Text()
		lArr := strings.Split(line, "\t")
		stype := lArr[0]

		if start {
			if stype == "txHash" && lArr[1] == hash.String() {
				break
			}
			switch stype {
			case "preStateRoot":
				txExtra.PreStateRoot = common.HexToHash(lArr[1])
			case "postStateRoot":
				txExtra.PostStateRoot = common.HexToHash(lArr[1])
			case "code":
				//if c, err := base64.StdEncoding.DecodeString(lArr[2]); err == nil {
				//	txExtra.AddCode(common.HexToAddress(lArr[1]), c)
				//}
			case "preState":
				if enc, err := base64.StdEncoding.DecodeString(lArr[2]); err == nil {
					data := new(StateAccount)
					if err := rlp.DecodeBytes(enc, data); err != nil {
						//txExtra.AddPreState(common.HexToAddress(lArr[1]), &StateAccount{
						//	Nonce:    0,
						//	Balance:  new(big.Int),
						//	Root:     emptyRoot,
						//	CodeHash: emptyCodeHash,
						//})
						//log.Error("ReadFileByHash Failed to decode state object", "addr", common.HexToAddress(lArr[1]), "err", err)
					} else {
						txExtra.AddPreState(common.HexToAddress(lArr[1]), data)
					}
				}
			case "postState":
				if c, err := base64.StdEncoding.DecodeString(lArr[2]); err == nil {
					txExtra.AddPostState(common.HexToAddress(lArr[1]), c)
				}
			case "preStateProof":
				var path [][]byte
				for _, s := range lArr[2:] {
					if c, err := base64.StdEncoding.DecodeString(s); err == nil {
						path = append(path, c)
					}
				}
				txExtra.AddPreStateProof(common.HexToAddress(lArr[1]), path)
			case "postStateProof":
				var path [][]byte
				for _, s := range lArr[2:] {
					if c, err := base64.StdEncoding.DecodeString(s); err == nil {
						path = append(path, c)
					}
				}
				txExtra.AddPostStateProof(common.HexToAddress(lArr[1]), path)
			case "preStorage":
				//log.Info("preStorage", "address", lArr[1], "hash", lArr[2], "val", lArr[3])
				txExtra.AddPreStorage(common.HexToAddress(lArr[1]), common.HexToHash(lArr[2]), common.HexToHash(lArr[3]))
				//log.Info("preStorage", "extra.PreStorage", extraData.PreStorageData.List)
			case "postStorage":
				//log.Info("postStorage", "address", lArr[1], "hash", lArr[2], "val", lArr[3])
				txExtra.AddPostStorage(common.HexToAddress(lArr[1]), common.HexToHash(lArr[2]), common.HexToHash(lArr[3]))
			case "preStorageProof":
				var path [][]byte
				for _, s := range lArr[3:] {
					if c, err := base64.StdEncoding.DecodeString(s); err == nil {
						path = append(path, c)
					}
				}
				txExtra.AddPreStorageProof(common.HexToAddress(lArr[1]), common.HexToHash(lArr[2]), path)
			case "postStorageProof":
				var path [][]byte
				for _, s := range lArr[3:] {
					if c, err := base64.StdEncoding.DecodeString(s); err == nil {
						path = append(path, c)
					}
				}
				txExtra.AddPostStorageProof(common.HexToAddress(lArr[1]), common.HexToHash(lArr[2]), path)

			case "preCode":
				if c, err := base64.StdEncoding.DecodeString(lArr[2]); err == nil {
					txExtra.AddPreCode(common.HexToAddress(lArr[1]), c)
				}
			case "postCode":
				if c, err := base64.StdEncoding.DecodeString(lArr[2]); err == nil {
					txExtra.AddPostCode(common.HexToAddress(lArr[1]), c)
				}
			default:
			}
		}
		if stype == "txHash" && lArr[1] == hash.String() {
			start = true
		}
	}
	return txExtra
}

type ExtraProof struct {
	List map[common.Hash][]byte
}

func (e *ExtraProof) Has(key []byte) (bool, error) {
	if e.List[common.BytesToHash(key)] == nil {
		return false, nil
	}
	return true, nil
}

func (e *ExtraProof) Get(key []byte) ([]byte, error) {
	if data := e.List[common.BytesToHash(key)]; data != nil {
		return data, nil
	}
	return nil, nil
}

func NewExtraProof(b [][]byte) *ExtraProof {
	proof := map[common.Hash][]byte{}
	for _, bytes := range b {
		temp := crypto.Keccak256(bytes)
		proof[common.BytesToHash(temp)] = bytes
	}
	return &ExtraProof{proof}
}
