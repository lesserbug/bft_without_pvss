package main

import (
	"crypto/ed25519"

	"crypto/sha256"
	"encoding/json"
	"fmt"

	// "strconv"

	"time"
)

type Message struct {
	Type      string
	Content   []byte
	Signature []byte
	SenderID  int
}

func (sbft *SleepyBFT) HandleMessage(msg Message) {
	sbft.mutex.Lock()
	if _, exists := sbft.messageQueues[msg.Type]; !exists {
		fmt.Println("Unknown message type:", msg.Type)
		sbft.mutex.Unlock()
		return
	}

	// Add message to the queue
	sbft.messageQueues[msg.Type] = append(sbft.messageQueues[msg.Type], msg)
	sbft.mutex.Unlock()

	// Optionally, start processing the queue with a delay
	sbft.setQueueTimer(msg.Type)
}

func (sbft *SleepyBFT) setQueueTimer(messageType string) {
	var delay time.Duration
	switch messageType {
	case "proposal":
		delay = 2 * time.Second
	case "vote":
		delay = 2 * time.Second
	case "confirmation":
		delay = 2 * time.Second
	default:
		delay = 2 * time.Second
	}

	time.AfterFunc(delay, func() {
		sbft.processMessageQueue(messageType)
	})
}

func (sbft *SleepyBFT) processMessageQueue(messageType string) {
	sbft.mutex.Lock()
	if len(sbft.messageQueues[messageType]) == 0 {
		sbft.mutex.Unlock()
		return
	}
	message := sbft.messageQueues[messageType][0]
	sbft.messageQueues[messageType] = sbft.messageQueues[messageType][1:]
	sbft.mutex.Unlock()

	// Process the message based on its type
	switch messageType {
	case "proposal":
		sbft.HandleProposal(message)
	case "vote":
		sbft.HandleVote(message)
	case "confirmation":
		sbft.HandleConfirmation(message)
	}

	// Check if more messages need to be processed and set timer again
	sbft.mutex.Lock()
	if len(sbft.messageQueues[messageType]) > 0 {
		sbft.mutex.Unlock()
		sbft.setQueueTimer(messageType)
	} else {
		sbft.mutex.Unlock()
	}
}

func (sbft *SleepyBFT) HandleProposal(msg Message) {
	sbft.mutex.Lock()
	defer sbft.mutex.Unlock()

	// Find the public key by iterating over the Nodes slice
	var proposalPublicKey ed25519.PublicKey
	found := false
	for _, node := range sbft.Nodes {
		if node.ID == msg.SenderID {
			proposalPublicKey = getPubKey(node.ID)
			found = true
			break
		}
	}

	if !found {
		fmt.Println("No public key found for Node ID", msg.SenderID)
		return
	}

	// Verifying the signature
	if !ed25519.Verify(proposalPublicKey, msg.Content, msg.Signature) {
		fmt.Println("Invalid signature from Node", msg.SenderID)
		return
	}

	var proposalData struct {
		Block     Block
		BlockHash [32]byte
		VRFData   VRFData
		ID        int
	}

	err := json.Unmarshal(msg.Content, &proposalData)
	if err != nil {
		fmt.Println("Error unmarshalling proposal data:", err)
		return
	}

	// Verify block hash
	blockData, err := json.Marshal(proposalData.Block)
	if err != nil {
		fmt.Println("Error marshalling block data:", err)
		return
	}
	computedHash := sha256.Sum256(blockData)
	if computedHash != proposalData.BlockHash {
		fmt.Println("Invalid block hash from Node", proposalData.ID)
		return
	}

	sbft.VRFValues[proposalData.ID] = proposalData.VRFData.Value
	sbft.Block[msg.SenderID] = proposalData.Block

	// Check if all VRF values are received
	if len(sbft.VRFValues) > len(sbft.Nodes) {
		leaderID := sbft.determineLeader()
		sbft.LeaderId = leaderID
		fmt.Println("Node", sbft.node.ID, "determines Leader is Node:", leaderID)

		go sbft.castVote(leaderID)
	}
}

func (sbft *SleepyBFT) castVote(LeaderID int) {
	sbft.mutex.Lock()
	if sbft.VoteSent {
		sbft.mutex.Unlock()
		return
	}
	sbft.VoteSent = true
	sbft.mutex.Unlock()

	if sbft.node.isMalicious {
		for id := range sbft.Block {
			voteData := struct {
				NodeID      int
				CurrentView int
			}{
				NodeID:      id,
				CurrentView: sbft.State.CurrentView,
			}

			voteContent, err := json.Marshal(voteData)
			if err != nil {
				fmt.Println("Error marshalling vote data:", err)
				return
			}

			voteSignature := ed25519.Sign(sbft.node.PrivateKey, voteContent)

			voteMsg := Message{
				Type:      "vote",
				Content:   voteContent,
				Signature: voteSignature,
				SenderID:  sbft.node.ID,
			}

			sbft.BroadcastMessage(voteMsg)
			// fmt.Printf("Malicious Node %d: cast vote for block with Leader ID %d\n", sbft.node.ID, id)
		}
	} else {
		voteData := struct {
			NodeID      int
			CurrentView int
		}{
			NodeID:      LeaderID,
			CurrentView: sbft.State.CurrentView,
		}

		voteContent, err := json.Marshal(voteData)
		if err != nil {
			fmt.Println("Error marshalling vote data:", err)
			return
		}

		voteSignature := ed25519.Sign(sbft.node.PrivateKey, voteContent)
		voteMsg := Message{
			Type:      "vote",
			Content:   voteContent,
			Signature: voteSignature,
			SenderID:  sbft.node.ID,
		}

		sbft.BroadcastMessage(voteMsg)
		// fmt.Println("Node", sbft.node.ID, "cast vote for block with Leader ID", LeaderID)
	}
}

func (sbft *SleepyBFT) HandleVote(msg Message) {
	var voteData struct {
		NodeID        int
		CurrentView   int
		EligibleNodes map[int]bool
	}

	err := json.Unmarshal(msg.Content, &voteData)
	if err != nil {
		fmt.Println("Error unmarshalling vote data:", err)
		return
	}

	sbft.mutex.Lock()
	defer sbft.mutex.Unlock()

	proposalPublicKey := getPubKey(msg.SenderID)
	// Verifying the signature
	if !ed25519.Verify(proposalPublicKey, msg.Content, msg.Signature) {
		fmt.Println("Invalid signature from Node", msg.SenderID)
		return
	}

	if voteData.NodeID == sbft.LeaderId {
		sbft.VotesCount[voteData.NodeID]++
		count := sbft.VotesCount[sbft.LeaderId]
		alreadyConfirmed := sbft.ConfirmationSent

		if count > len(sbft.Nodes)*2/3 && !alreadyConfirmed {
			go sbft.broadcastConfirmation(sbft.LeaderId)
		}
	}

}

func (sbft *SleepyBFT) broadcastConfirmation(leaderID int) {

	if sbft.ConfirmationSent {
		return
	}
	sbft.ConfirmationSent = true

	msgContent, err := json.Marshal(struct {
		LeaderID int
	}{
		LeaderID: leaderID,
	})
	if err != nil {
		fmt.Println("Error marshalling confirmation data:", err)
		return
	}

	fmt.Println("Node", sbft.node.ID, "sending confirmation for block with Leader ID", leaderID)

	for _, node := range sbft.Nodes {
		if node.ID != sbft.node.ID {
			sbft.SendMessage(node.Address, Message{
				Type:     "confirmation",
				Content:  msgContent,
				SenderID: sbft.node.ID,
			})
		}
	}
}

// HandleConfirmation adapted for SleepyBFT (implementation needed)
func (sbft *SleepyBFT) HandleConfirmation(msg Message) {

	var confirmationData struct {
		LeaderID int
	}
	err := json.Unmarshal(msg.Content, &confirmationData)
	if err != nil {
		fmt.Println("Error unmarshalling confirmation data:", err)
		return
	}

	sbft.mutex.Lock()
	defer sbft.mutex.Unlock()

	sbft.confirmationList[confirmationData.LeaderID]++

	// if (sbft.confirmationList[confirmationData.LeaderID] > len(sbft.Nodes)*2/3) && !sbft.ConfirmationReceived {
	//  fmt.Println("Node", sbft.node.ID, "received enough confirmation for LeaderID", confirmationData.LeaderID)
	//  sbft.ConfirmationReceived = true

	//  leaderBlock := sbft.Block[confirmationData.LeaderID]

	//  if len(sbft.Chain) > 0 {
	//      expectedHeight := sbft.Chain[len(sbft.Chain)-1].Height + 1
	//      expectedPrevHash := getBlockHash(sbft.Chain[len(sbft.Chain)-1])

	//      if leaderBlock.Height != expectedHeight || leaderBlock.PrevHash != expectedPrevHash {
	//          sbft.ForkCount++
	//      }
	//  }

	//  sbft.Chain = append(sbft.Chain, leaderBlock)

	//  // 记录数据
	//  // sbft.fileMutex.Lock()
	//  // sbft.csvWriter.Write([]string{
	//  //  strconv.Itoa(sbft.currentRound),
	//  //  strconv.Itoa(sbft.node.ID),
	//  //  strconv.Itoa(len(sbft.Chain)),
	//  //  strconv.Itoa(sbft.ForkCount),
	//  // })
	//  // sbft.csvWriter.Flush()
	//  // sbft.fileMutex.Unlock()
	//  // Send data through channel
	//  sbft.dataChan <- RoundData{
	//      Round:       sbft.currentRound,
	//      NodeID:      sbft.node.ID,
	//      ChainLength: len(sbft.Chain),
	//      ForkCount:   sbft.ForkCount,
	//  }
	if sbft.confirmationList[confirmationData.LeaderID] > len(sbft.Nodes)*2/3 && !sbft.ConfirmationReceived {
		leaderBlock := sbft.Block[confirmationData.LeaderID]

		if len(sbft.MainChain) > 0 {
			expectedHeight := sbft.MainChain[len(sbft.MainChain)-1].Height + 1
			expectedPrevHash := getBlockHash(sbft.MainChain[len(sbft.MainChain)-1])

			if leaderBlock.Height != expectedHeight || leaderBlock.PrevHash != expectedPrevHash {
				// 处理分叉
				sbft.handleFork(leaderBlock)
			} else {
				// 没有分叉，直接添加到主链
				sbft.MainChain = append(sbft.MainChain, leaderBlock)
				sbft.updateLongestChainLength()
			}
		} else {
			// 这是第一个区块
			sbft.MainChain = append(sbft.MainChain, leaderBlock)
			sbft.LongestChainLength = 1
		}

		sbft.ConfirmationReceived = true

		go sbft.reportData()

		go sbft.startNextPhase()
	}
}

func (sbft *SleepyBFT) startNextPhase() {
	// 延迟1秒启动下一轮
	time.AfterFunc(2*time.Second, func() {
		sbft.State.CurrentView++
		sbft.currentRound++
		sbft.selfProposalSent = false
		sbft.ConfirmationSent = false
		sbft.ConfirmationReceived = false
		sbft.VoteSent = false

		sbft.mutex.Lock()
		// Reset all stored values to initiate a new round
		sbft.VRFValues = make(map[int][]byte)
		sbft.Block = make(map[int]Block)
		sbft.VotesCount = make(map[int]int)
		sbft.confirmationList = make(map[int]int)
		sbft.ProposalSent = make(map[int]bool)

		sbft.mutex.Unlock()

		go sbft.SendProposal() // Start the next proposal phase
	})
}

func getBlockHash(block Block) string {
	blockData, _ := json.Marshal(block)
	return fmt.Sprintf("%x", sha256.Sum256(blockData))
}

func (sbft *SleepyBFT) reportData() {
	sbft.dataChan <- RoundData{
		Round:       sbft.currentRound,
		NodeID:      sbft.node.ID,
		LeaderID:    sbft.LeaderId,
		ChainLength: sbft.LongestChainLength,
		ForkCount:   sbft.TotalForks,
	}
}

func (sbft *SleepyBFT) handleFork(newBlock Block) {
	forkStartHeight := newBlock.Height

	if _, exists := sbft.ForkChains[forkStartHeight]; !exists {
		// 新的分叉点
		sbft.ForkChains[forkStartHeight] = []Block{newBlock}
		sbft.TotalForks++
	} else {
		// 检查是否是已知分叉的延续或新分叉
		isNewFork := true
		for i, fork := range sbft.ForkChains[forkStartHeight] {
			if fork.PrevHash == newBlock.PrevHash {
				// 已知分叉的延续
				sbft.ForkChains[forkStartHeight] = append(sbft.ForkChains[forkStartHeight][:i+1], newBlock)
				isNewFork = false
				break
			}
		}
		if isNewFork {
			// 在同一高度的新分叉
			sbft.ForkChains[forkStartHeight] = append(sbft.ForkChains[forkStartHeight], newBlock)
			sbft.TotalForks++
		}
	}

	sbft.checkAndUpdateMainChain()
}

func (sbft *SleepyBFT) checkAndUpdateMainChain() {
	for startHeight, forkChain := range sbft.ForkChains {
		if len(sbft.MainChain)-startHeight+len(forkChain) > sbft.LongestChainLength {
			// 这个分叉链加上之前的主链部分比当前最长链还长
			newMainChain := append(sbft.MainChain[:startHeight], forkChain...)
			sbft.MainChain = newMainChain
			sbft.updateLongestChainLength()

			// 清理旧的分叉
			for h := range sbft.ForkChains {
				if h <= startHeight {
					delete(sbft.ForkChains, h)
				}
			}
			break
		}
	}
}

func (sbft *SleepyBFT) updateLongestChainLength() {
	sbft.LongestChainLength = len(sbft.MainChain)
	for _, forkChain := range sbft.ForkChains {
		if len(forkChain)+(sbft.MainChain[len(sbft.MainChain)-1].Height-forkChain[0].Height+1) > sbft.LongestChainLength {
			sbft.LongestChainLength = len(forkChain) + (sbft.MainChain[len(sbft.MainChain)-1].Height - forkChain[0].Height + 1)
		}
	}
}
