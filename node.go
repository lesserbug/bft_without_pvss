package main

import (
	// "crypto"
	"crypto/ed25519"
	"crypto/sha256"

	// "encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/torusresearch/pvss/common"
	// "github.com/torusresearch/pvss/secp256k1"
)

type VSSData struct {
	Shares  []byte
	Commits []byte
}

type VRFData struct {
	Value []byte
	Proof []byte
}

type Commitment struct {
	X []byte
	Y []byte
}

type NodeState struct {
	CurrentView        int
	CurrentPhase       int
	InactiveNodeCounts map[int]int
	NodeTimers         map[int]*time.Timer
	VerificationTimers map[int]*time.Timer
	SleepyNodes        map[int]bool
}

type Node struct {
	ID         int
	Address    string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// 新增PVSSNode结构体用于PVSS
type PVSSNode struct {
	Index  int
	PubKey common.Point
}

type Block struct {
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
	Shares    map[int][]byte
	// LeaderShares map[int][]byte // This map holds shares only from the leader during verification
	ShareIndex                 map[int]int
	testShare                  map[int]common.PrimaryShare
	testLeaderShare            map[int]common.PrimaryShare
	Commits                    map[int]Commitment
	VotesCount                 map[int]int
	VotesConfirmed             map[int]bool
	ProposalSent               map[int]bool
	selfProposalSent           bool
	ShareSent                  bool
	VoteSent                   bool
	ConfirmationSent           bool
	ConfirmationReceived       bool
	NextRoundCommitments       map[int]bool
	NextRoundCommitCount       map[int]int
	EligibleNextRound          map[int]bool
	ConfirmedEligibleNextRound map[int]int
	FinalEligibleNextRound     map[int]bool
	Signatures                 [][]byte       // 用于存储单个节点的签名
	NodeSignatures             map[int][]byte // 节点ID与其签名的映射
	NodeMessages               map[int][]byte // 节点ID与其对应的消息内容的映射
	AggregatedSignature        []byte         // 存储聚合后的签名
	AggregatedNodes            []int          // 存储参与聚合的节点ID
	confirmationList           map[int]int
	mutex                      sync.Mutex
	proposalCache              []Message
	verificationCache          []Message
	voteCache                  []Message
	confirmationCache          []Message
}

func NewSleepyBFT(nodeID int, addr string) *SleepyBFT {
	b := new(SleepyBFT)
	b.node.ID = nodeID
	b.node.Address = addr
	b.node.PrivateKey = getPrivKey(nodeID)
	b.node.PublicKey = getPubKey(nodeID)
	b.Nodes = make([]Node, 0)
	b.PVSSNodes = make([]PVSSNode, 0) // 初始化空的PVSS node list
	b.Block = make(map[int]Block)
	b.VRFValues = make(map[int][]byte)
	b.Shares = make(map[int][]byte)
	b.ShareIndex = make(map[int]int)
	b.Commits = make(map[int]Commitment)
	b.testShare = make(map[int]common.PrimaryShare)
	b.testLeaderShare = make(map[int]common.PrimaryShare)
	b.VotesCount = make(map[int]int)
	b.VotesConfirmed = make(map[int]bool)
	b.ProposalSent = make(map[int]bool)
	b.selfProposalSent = false
	b.ShareSent = false
	b.VoteSent = false
	b.ConfirmationSent = false
	b.ConfirmationReceived = false
	b.NextRoundCommitments = make(map[int]bool)
	b.NextRoundCommitCount = make(map[int]int)
	b.EligibleNextRound = make(map[int]bool)
	b.ConfirmedEligibleNextRound = make(map[int]int)
	b.FinalEligibleNextRound = make(map[int]bool)

	b.Signatures = make([][]byte, 0)
	b.NodeSignatures = make(map[int][]byte)
	b.NodeMessages = make(map[int][]byte)
	b.AggregatedSignature = make([]byte, 0)
	b.AggregatedNodes = make([]int, 0)

	b.confirmationList = make(map[int]int)

	b.State = NodeState{
		CurrentView:  1,
		CurrentPhase: 0,
		// Timer:        time.NewTimer(0),
		InactiveNodeCounts: make(map[int]int),
	}
	b.State.NodeTimers = make(map[int]*time.Timer)
	b.State.VerificationTimers = make(map[int]*time.Timer)
	b.State.SleepyNodes = make(map[int]bool)

	// 初始化每个节点的不活跃计数
	for _, node := range b.Nodes {
		b.State.InactiveNodeCounts[node.ID] = 0
	}

	b.proposalCache = make([]Message, 0)
	b.verificationCache = make([]Message, 0)
	b.voteCache = make([]Message, 0)
	b.confirmationCache = make([]Message, 0)

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
		if node.ID != sbft.node.ID && sbft.FinalEligibleNextRound[node.ID] {
			sbft.SendMessage(node.Address, msg)
		}
	}
}

func (sbft *SleepyBFT) SendProposal() {
	sbft.State.CurrentPhase = 1 // 1表示提议阶段
	for _, timer := range sbft.State.NodeTimers {
		if timer != nil {
			timer.Stop()
		}
	}
	for _, node := range sbft.Nodes {
		if sbft.FinalEligibleNextRound[node.ID] {
			nodeID := node.ID
			if _, ok := sbft.State.NodeTimers[nodeID]; !ok {
				sbft.State.NodeTimers[nodeID] = time.AfterFunc(time.Second, func() {
					sbft.markNodeAsSleepy(nodeID)
				})
			} else {
				sbft.State.NodeTimers[nodeID].Reset(time.Second)
			}
		}
	}

	timestamp := time.Now().Unix()
	vrfMessage := []byte(strconv.Itoa(sbft.node.ID) + strconv.Itoa(int(timestamp)) + strconv.Itoa(rand.Intn(100)))

	pi, vrfOutput, err := Prove(sbft.node.PublicKey, sbft.node.PrivateKey, vrfMessage)
	if err != nil {
		fmt.Println("Error generating VRF:", err)
		return
	}

	sbft.VRFValues[sbft.node.ID] = vrfOutput
	// fmt.Println("Self Node", sbft.node.ID,"store VRF output:", sbft.VRFValues)

	// block := []byte("Block Message: block_" + strconv.Itoa(sbft.node.ID) + strconv.Itoa(rand.Intn(100)) + "PrevHash: previous-block-hash previous-block-hash previous-block-hash previous-block-hash qsqidhqwioudgqwiushqioasdnqwuodg	qwuiSGB	QWLDGUI	DHSODHQIORHQOWHO	djwdsiofhqiohhhhhhhhhhhhhhhhhhhhhfcwdjoqihdqo")
	block := Block{
		PrevHash:  "previous-block-hash",
		Message:   "Block Message: block_" + strconv.Itoa(sbft.node.ID),
		RandomNum: rand.Intn(100),
	}

	blockData, err := json.Marshal(block)
	if err != nil {
		fmt.Println("Error marshalling block:", err)
		return
	}

	hash := sha256.Sum256(blockData)
	hashBigInt := new(big.Int).SetBytes(hash[:])

	// // 截取前8个字节
	// truncatedHash := hash[:8]
	// secret := new(big.Int).SetBytes(truncatedHash)

	// 定义模数
	// modulus := new(big.Int)
	// modulus.SetString("340282366920938463463374607431768211456", 10) // 10表示十进制
	// secret := new(big.Int).Mod(hashBigInt, modulus)

	secret := hashBigInt
	fmt.Println("Node", sbft.node.ID, "secret:", secret)

	commonNodes := make([]common.Node, len(sbft.PVSSNodes))
	for i, pvssNode := range sbft.PVSSNodes {
		commonNodes[i] = common.Node{
			Index:  pvssNode.Index,
			PubKey: pvssNode.PubKey,
		}
	}

	shares, commits, err := CreateShares(commonNodes, *secret, len(sbft.Nodes))
	if err != nil {
		fmt.Println("Error creating PVSS shares:", err)
		return
	}

	// // 验证每个分享
	// allValid := true
	// for i, share := range *shares {
	// 	if !verifyShareUsingCommits(share, *commits) {
	// 		fmt.Println("Verification failed for share:", i)
	// 		allValid = false
	// 	}
	// }

	// if allValid {
	// 	fmt.Println("All shares and commits verified successfully.")
	// } else {
	// 	fmt.Println("Verification failed for one or more shares or commits.")
	// }

	serializedCommits := make(map[int]Commitment)
	for i, commit := range *commits {
		serializedCommits[i] = Commitment{
			X: commit.X.Bytes(),
			Y: commit.Y.Bytes(),
		}
	}

	// Store own commitments
	sbft.Commits = serializedCommits

	// reconstructedSecret := LagrangeScalar(*shares, 0) // 目标索引0，用于重建原始秘密
	// reconstructedMessage := string(reconstructedSecret.Bytes())

	// // Store its own share and commit directly
	sbft.Shares[sbft.node.ID] = (*shares)[0].Value.Bytes()
	sbft.ShareIndex[sbft.node.ID] = (*shares)[0].Index
	sbft.testShare[sbft.node.ID] = (*shares)[0]

	sbft.NextRoundCommitments[sbft.node.ID] = true

	sbft.Block[sbft.node.ID] = block

	for i, node := range sbft.Nodes {
		if node.ID != sbft.node.ID && sbft.FinalEligibleNextRound[node.ID] && !sbft.ProposalSent[node.ID] {
			content, err := json.Marshal(struct {
				Block       Block
				ShareValue  []byte
				ShareIndex  int
				VRFData     VRFData
				Commit      map[int]Commitment
				CommitmentP bool
				ID          int
			}{
				Block:       block,
				ShareValue:  (*shares)[i+1].Value.Bytes(),
				ShareIndex:  (*shares)[i+1].Index, // Include share index
				VRFData:     VRFData{Value: vrfOutput, Proof: pi},
				Commit:      serializedCommits,
				CommitmentP: true,
				ID:          sbft.node.ID,
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
			fmt.Println("Node", sbft.node.ID, "send proposal to", node.ID)
			sbft.ProposalSent[node.ID] = true
		}
	}
	sbft.selfProposalSent = true

	// sbft.mutex.Lock()
	fmt.Println("Node", sbft.node.ID, "begin handle cache proposal message")
	for _, cachedMsg := range sbft.proposalCache {
		// fmt.Println(cachedMsg.SenderID)
		sbft.HandleProposal(cachedMsg) // 处理每一个缓存的提案
	}
	sbft.proposalCache = nil // 清空缓存
	// sbft.mutex.Unlock()
}

func (sbft *SleepyBFT) markNodeAsSleepy(nodeID int) {
	sbft.mutex.Lock()
	defer sbft.mutex.Unlock()
	if _, received := sbft.Shares[nodeID]; !received {
		sbft.State.InactiveNodeCounts[nodeID]++
		sbft.State.SleepyNodes[nodeID] = true
		fmt.Println("Node", nodeID, "is marked as sleepy due to timeout by node", sbft.node.ID)
	}
}

func (sbft *SleepyBFT) markVeriNodeAsSleepy(nodeID int) {
	sbft.mutex.Lock()
	defer sbft.mutex.Unlock()
	if _, received := sbft.testLeaderShare[nodeID]; !received {
		sbft.State.InactiveNodeCounts[nodeID]++
		sbft.State.SleepyNodes[nodeID] = true
		fmt.Println("Node", nodeID, "is marked as sleepy due to timeout by node", sbft.node.ID)
	}
}

func (sbft *SleepyBFT) broadcastAwake() {
	awakeMessage := Message{
		Type:     "awake",
		Content:  []byte("Awake message"),
		SenderID: sbft.node.ID,
	}

	sbft.BroadcastMessage(awakeMessage)
	fmt.Println("Node", sbft.node.ID, "broadcasts awake message")
}
