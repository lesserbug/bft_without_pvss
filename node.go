package main

import (
	"crypto/ed25519"
	"crypto/sha256"

	"encoding/json"
	"fmt"

	// "encoding/csv"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/torusresearch/pvss/common"
)

type VRFData struct {
	Value []byte
	Proof []byte
}

type Commitment struct {
	X []byte
	Y []byte
}

type NodeState struct {
	CurrentView  int
	CurrentPhase int
}

type Node struct {
	ID          int
	Address     string
	PublicKey   ed25519.PublicKey
	PrivateKey  ed25519.PrivateKey
	isMalicious bool
}

// 新增PVSSNode结构体用于PVSS
type PVSSNode struct {
	Index  int
	PubKey common.Point
}

type RoundData struct {
	Round       int
	NodeID      int
	LeaderID    int
	ChainLength int
	ForkCount   int
}

type Block struct {
	Height    int    `json:"Height"`
	PrevHash  string `json:"PrevHash"`
	Message   string `json:"Message"`
	RandomNum int    `json:"randomNum"`
}

// SleepyBFT structure includes Node and other properties
type SleepyBFT struct {
	node      Node
	State     NodeState
	Nodes     []Node
	PVSSNodes []PVSSNode
	LeaderId  int
	Block     map[int]Block
	VRFValues map[int][]byte

	VotesCount           map[int]int
	VotesConfirmed       map[int]bool
	ProposalSent         map[int]bool
	selfProposalSent     bool
	VoteSent             bool
	ConfirmationSent     bool
	ConfirmationReceived bool

	confirmationList map[int]int
	mutex            sync.Mutex

	messageQueues map[string][]Message

	ForkCount int
	fileMutex sync.Mutex

	currentRound int
	targetRound  int

	dataChan chan RoundData

	MainChain          []Block
	ForkChains         map[int][]Block // 键是分叉起始的高度
	TotalForks         int
	LongestChainLength int
}

func NewSleepyBFT(nodeID int, addr string, isMalicious bool, dataChan chan RoundData, targetRound int) *SleepyBFT {
	b := new(SleepyBFT)
	b.node.ID = nodeID
	b.node.Address = addr
	b.node.PrivateKey = getPrivKey(nodeID)
	b.node.PublicKey = getPubKey(nodeID)
	b.node.isMalicious = isMalicious
	b.Nodes = make([]Node, 0)
	b.PVSSNodes = make([]PVSSNode, 0) // 初始化空的PVSS node list
	b.Block = make(map[int]Block)
	b.VRFValues = make(map[int][]byte)

	b.VotesCount = make(map[int]int)
	b.VotesConfirmed = make(map[int]bool)
	b.ProposalSent = make(map[int]bool)
	b.selfProposalSent = false

	b.VoteSent = false
	b.ConfirmationSent = false
	b.ConfirmationReceived = false

	b.confirmationList = make(map[int]int)

	b.State = NodeState{
		CurrentView:  1,
		CurrentPhase: 0,
	}

	b.messageQueues = make(map[string][]Message)
	b.messageQueues["proposal"] = []Message{}
	b.messageQueues["verification"] = []Message{}
	b.messageQueues["vote"] = []Message{}
	b.messageQueues["confirmation"] = []Message{}

	b.ForkCount = 0
	// b.csvWriter = writer
	b.fileMutex = sync.Mutex{}

	b.currentRound = 1
	b.targetRound = targetRound
	b.dataChan = dataChan

	b.MainChain = make([]Block, 0)
	b.ForkChains = make(map[int][]Block)
	b.TotalForks = 0
	b.LongestChainLength = 0
	return b
}

func (sbft *SleepyBFT) Listen() {
	listener, err := net.Listen("tcp", sbft.node.Address)
	if err != nil {
		fmt.Println("Error starting server:", err)
		panic(err)
	}
	defer listener.Close()

	fmt.Println("NodeID: ", sbft.node.ID, "listening on", sbft.node.Address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go sbft.HandleConnection(conn)
	}
}

// HandleConnection method adapted for SleepyBFT
func (sbft *SleepyBFT) HandleConnection(conn net.Conn) {
	defer conn.Close()
	decoder := json.NewDecoder(conn)

	var msg Message
	err := decoder.Decode(&msg)
	if err != nil {
		fmt.Println("Error decoding message:", err)
		return
	}

	sbft.HandleMessage(msg)
}

// SendMessage method adapted for SleepyBFT
func (sbft *SleepyBFT) SendMessage(address string, msg Message) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	err = encoder.Encode(msg)
	if err != nil {
		fmt.Println("Error encoding and sending message:", err)
	}
}

// BroadcastMessage method adapted for SleepyBFT
func (sbft *SleepyBFT) BroadcastMessage(msg Message) {
	for _, node := range sbft.Nodes {
		if node.ID != sbft.node.ID {
			sbft.SendMessage(node.Address, msg)
		}
	}
}

func (sbft *SleepyBFT) SendProposal() {
	sbft.State.CurrentPhase = 1 // 1表示提议阶段

	timestamp := time.Now().Unix()
	vrfMessage := []byte(strconv.Itoa(sbft.node.ID) + strconv.Itoa(int(timestamp)) + strconv.Itoa(rand.Intn(100)))

	pi, vrfOutput, err := Prove(sbft.node.PublicKey, sbft.node.PrivateKey, vrfMessage)
	if err != nil {
		fmt.Println("Error generating VRF:", err)
		return
	}

	sbft.VRFValues[sbft.node.ID] = vrfOutput

	var prevHash string
	var height int
	if len(sbft.MainChain) == 0 {
		prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
		height = 0
	} else {
		prevBlock := sbft.MainChain[len(sbft.MainChain)-1]
		prevHash = getBlockHash(prevBlock)
		height = prevBlock.Height + 1
	}
	block := Block{
		Height:    height,
		PrevHash:  prevHash,
		Message:   "Block Message: block_" + strconv.Itoa(sbft.node.ID),
		RandomNum: rand.Intn(100),
	}

	blockData, err := json.Marshal(block)
	if err != nil {
		fmt.Println("Error marshalling block:", err)
		return
	}

	blockHash := sha256.Sum256(blockData)
	sbft.Block[sbft.node.ID] = block

	if sbft.node.isMalicious {

		block2 := Block{
			Height:    height,
			PrevHash:  prevHash,
			Message:   "Block Message: block_" + strconv.Itoa(sbft.node.ID) + "_2",
			RandomNum: rand.Intn(100),
		}

		for i, node := range sbft.Nodes {
			if node.ID != sbft.node.ID && !sbft.ProposalSent[node.ID] {
				block1 := block2
				if i%2 == 1 {
					block1 = block
				}
				blockfaultData, _ := json.Marshal(block1)
				content, err := json.Marshal(struct {
					Block     Block
					BlockHash [32]byte
					VRFData   VRFData
					ID        int
				}{
					Block:     block1,
					BlockHash: sha256.Sum256(blockfaultData),
					VRFData:   VRFData{Value: vrfOutput, Proof: pi},
					ID:        sbft.node.ID,
				})

				if err != nil {
					fmt.Println("Error marshalling VSS share and commit data:", err)
					return
				}

				signature := ed25519.Sign(sbft.node.PrivateKey, content)
				msg := Message{
					Type:      "proposal",
					Content:   content,
					Signature: signature,
					SenderID:  sbft.node.ID,
				}

				sbft.SendMessage(node.Address, msg)
				sbft.ProposalSent[node.ID] = true
			}
		}
	} else {
		for _, node := range sbft.Nodes {
			if node.ID != sbft.node.ID && !sbft.ProposalSent[node.ID] {

				content, err := json.Marshal(struct {
					Block     Block
					BlockHash [32]byte
					VRFData   VRFData
					ID        int
				}{
					Block:     block,
					BlockHash: blockHash,
					VRFData:   VRFData{Value: vrfOutput, Proof: pi},
					ID:        sbft.node.ID,
				})

				if err != nil {
					fmt.Println("Error marshalling VSS share and commit data:", err)
					return
				}

				signature := ed25519.Sign(sbft.node.PrivateKey, content)
				msg := Message{
					Type:      "proposal",
					Content:   content,
					Signature: signature,
					SenderID:  sbft.node.ID,
				}

				sbft.SendMessage(node.Address, msg)
				sbft.ProposalSent[node.ID] = true
			}
		}
	}

	fmt.Println("Node", sbft.node.ID, "send proposal")
	sbft.selfProposalSent = true
}
