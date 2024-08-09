package main

import (
	"crypto/ed25519"

	// "encoding/hex"

	// "encoding/base64"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"

	"time"

	bls "github.com/chuwt/chia-bls-go"

	"github.com/torusresearch/pvss/common"
)

type Message struct {
	Type      string
	Content   []byte
	Signature []byte
	SenderID  int
}

func (sbft *SleepyBFT) HandleMessage(msg Message) {
	switch msg.Type {
	case "proposal":
		sbft.HandleProposal(msg)
	case "verification":
		sbft.HandleVerification(msg)
	case "vote":
		sbft.HandleVote(msg)
	case "confirmation":
		sbft.HandleConfirmation(msg)
	case "awake":
		sbft.HandleAwake(msg)
	default:
		fmt.Println("Unknown message type:", msg.Type)
	}
}

// HandleProposal adapted for SleepyBFT
func (sbft *SleepyBFT) HandleProposal(msg Message) {
	if !sbft.selfProposalSent {
		// 如果还没有发送提案，先缓存这个消息
		sbft.proposalCache = append(sbft.proposalCache, msg)
		// sbft.mutex.Unlock()
		fmt.Println("Node", sbft.node.ID, "Caching proposal message from Node", msg.SenderID, "until local proposal is sent")
		return
	}

	if sbft.State.SleepyNodes[msg.SenderID] {
		fmt.Println("Ignoring message from sleepy node", msg.SenderID)
		return
	}
	if timer, ok := sbft.State.NodeTimers[msg.SenderID]; ok && timer != nil {
		timer.Stop()
	}

	// Find the public key by iterating over the Nodes slice
	var proposalPublicKey ed25519.PublicKey
	found := false
	for _, node := range sbft.Nodes {
		if node.ID == msg.SenderID {
			// proposalPublicKey = node.PublicKey
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
		Block       Block
		ShareValue  []byte
		ShareIndex  int
		Commit      map[int]Commitment
		VRFData     VRFData
		CommitmentP bool
		ID          int
	}

	err := json.Unmarshal(msg.Content, &proposalData)
	if err != nil {
		fmt.Println("Error unmarshalling proposal data:", err)
		return
	}

	// sbft.mutex.Lock()
	receivedShare := common.PrimaryShare{
		Index: proposalData.ShareIndex,
		Value: *new(big.Int).SetBytes(proposalData.ShareValue),
	}

	deserializedCommits := deserializeCommitments(proposalData.Commit)
	commitsList := convertCommitsMapToList(deserializedCommits)

	if !verifyShareUsingCommits(receivedShare, *commitsList) {
		fmt.Println("Share verification failed for Node", proposalData.ID)
		return
	}
	// else {
	// 	fmt.Println("Share verification succeeded for Node", proposalData.ID, "by Node", sbft.node.ID)
	// }

	fmt.Println("Node", sbft.node.ID, "received proposal with VRF from Node", proposalData.ID)

	// sbft.mutex.Lock()
	sbft.VRFValues[proposalData.ID] = proposalData.VRFData.Value
	sbft.Shares[proposalData.ID] = proposalData.ShareValue
	sbft.ShareIndex[proposalData.ID] = proposalData.ShareIndex

	sbft.NextRoundCommitments[proposalData.ID] = proposalData.CommitmentP

	sbft.Block[msg.SenderID] = proposalData.Block

	sbft.testShare[msg.SenderID] = receivedShare
	// sbft.mutex.Unlock()

	// Check if all VRF values are received
	// fmt.Println("NOde ID", sbft.node.ID, "VRF Length", len(sbft.VRFValues), "VRF", sbft.VRFValues,"Nodes num", len(sbft.Nodes), "Bool", sbft.ShareSent)
	if len(sbft.VRFValues) > len(sbft.Nodes) && !sbft.ShareSent {
		leaderID := sbft.determineLeader()
		sbft.LeaderId = leaderID
		sbft.testLeaderShare[sbft.node.ID] = sbft.testShare[leaderID]
		fmt.Println("Node", sbft.node.ID, "determines Leader is Node:", leaderID)
		// sbft.broadcastLeaderShare(leaderID, sbft.Shares[leaderID], sbft.ShareIndex[leaderID])

		time.AfterFunc(time.Second, func() {
			sbft.broadcastLeaderShare(leaderID)
		})

		// sbft.broadcastLeaderShare(leaderID)

		// if sbft.node.ID == 1 { // 假设节点ID为1是Node1
		// 	// 如果是Node1，则延迟5秒
		// 	time.AfterFunc(5*time.Second, func() {
		// 		sbft.broadcastLeaderShare(leaderID)
		// 	})
		// } else {
		// 	// 对于其他节点，延迟2秒
		// 	time.AfterFunc(2*time.Second, func() {
		// 		sbft.broadcastLeaderShare(leaderID)
		// 	})
		// }
	}

}

func (sbft *SleepyBFT) broadcastLeaderShare(leaderID int) {
	sbft.State.CurrentPhase = 2
	for _, timer := range sbft.State.VerificationTimers {
		if timer != nil {
			timer.Stop()
		}
	}
	for _, node := range sbft.Nodes {
		nodeID := node.ID // 创建一个局部变量的副本
		if _, ok := sbft.State.VerificationTimers[nodeID]; !ok {
			sbft.State.VerificationTimers[nodeID] = time.AfterFunc(time.Second, func() {
				sbft.markVeriNodeAsSleepy(nodeID) // 使用副本，确保每个计时器的闭包中的 nodeID 是正确的
			})
		} else {
			sbft.State.VerificationTimers[nodeID].Reset(time.Second)
		}
	}

	leaderShare := sbft.testLeaderShare[sbft.node.ID]
	for _, node := range sbft.Nodes {
		if node.ID != sbft.node.ID && sbft.FinalEligibleNextRound[node.ID] {
			msgContent, _ := json.Marshal(struct {
				LeaderID    int
				Share       []byte
				Index       int
				Commitments map[int]bool
			}{
				LeaderID:    leaderID,
				Share:       leaderShare.Value.Bytes(),
				Index:       leaderShare.Index,
				Commitments: sbft.NextRoundCommitments,
			})
			sbft.SendMessage(node.Address, Message{
				Type:     "verification",
				Content:  msgContent,
				SenderID: sbft.node.ID,
			})
		}
	}
	sbft.ShareSent = true // 标记分享已发送
	for _, cachedMsg := range sbft.verificationCache {
		sbft.HandleVerification(cachedMsg) // 处理缓存的验证消息
	}
	sbft.verificationCache = nil // 清空缓存
}

func (sbft *SleepyBFT) HandleVerification(msg Message) {
	if sbft.State.SleepyNodes[msg.SenderID] {
		fmt.Println("Ignoring message from sleepy node", msg.SenderID)
		return
	}
	if timer, ok := sbft.State.VerificationTimers[msg.SenderID]; ok && timer != nil {
		timer.Stop()
	}

	if !sbft.ShareSent {
		sbft.verificationCache = append(sbft.verificationCache, msg)
		fmt.Println("Node", sbft.node.ID, "Caching verification message from Node", msg.SenderID)
		return
	}

	var verificationData struct {
		LeaderID    int
		Share       []byte
		Index       int
		Commitments map[int]bool
	}

	if err := json.Unmarshal(msg.Content, &verificationData); err != nil {
		fmt.Println("Error unmarshalling verification data:", err)
		return
	}
	// receivedShare := common.PrimaryShare{
	// 	Index: verificationData.Index,
	// 	Value: *new(big.Int).SetBytes(verificationData.Share),
	// }

	// sbft.mutex.Lock()
	// sbft.testLeaderShare[msg.SenderID] = receivedShare
	// fmt.Println("Node", sbft.node.ID, "received verification data from Node", msg.SenderID, "with share lentgth:", len(sbft.testLeaderShare))
	// sbft.mutex.Unlock()

	// fmt.Println("Node", sbft.node.ID, "has testLeaderShare length:", len(sbft.testLeaderShare))

	if _, exists := sbft.testLeaderShare[msg.SenderID]; !exists { // 确保每个节点的数据只被处理一次
		receivedShare := common.PrimaryShare{
			Index: verificationData.Index,
			Value: *new(big.Int).SetBytes(verificationData.Share),
		}

		sbft.testLeaderShare[msg.SenderID] = receivedShare
		fmt.Println("Node", sbft.node.ID, "received verification data from Node", msg.SenderID)
	}

	// fmt.Println("Node", sbft.node.ID, "Commitments:", verificationData.Commitments)

	// 更新本地的Commitments统计
	for id, commit := range verificationData.Commitments {
		if commit {
			sbft.NextRoundCommitCount[id] += 1
		}
	}

	if len(sbft.testLeaderShare) >= len(sbft.Nodes)+1 {
		var shares []common.PrimaryShare
		for _, share := range sbft.testLeaderShare {
			shares = append(shares, share)
		}
		secret := LagrangeScalar(shares, 0)

		block, exists := sbft.Block[sbft.LeaderId]
		if !exists {
			fmt.Println("Block data missing for Node", sbft.LeaderId)
			return
		}

		blockData, err := json.Marshal(block)
		if err != nil {
			fmt.Println("Error marshalling block data:", err)
			return
		}
		hash := sha256.Sum256(blockData)
		computedHash := new(big.Int).SetBytes(hash[:])

		if secret.Cmp(computedHash) == 0 {
			fmt.Println("Node", sbft.node.ID, "Reconstructed and Verification successful for Node", sbft.LeaderId, "with secret:", secret)
		} else {
			fmt.Println("Verification failed for Node", sbft.LeaderId)
		}

		for id, count := range sbft.NextRoundCommitCount {
			if count > len(sbft.Nodes)*2/3 { // 假设使用2/3的节点数作为阈值
				sbft.EligibleNextRound[id] = true
			}
		}
		// fmt.Println("Node", sbft.node.ID, "NextRoundCommitCount:", sbft.NextRoundCommitCount)

		time.AfterFunc(time.Second, func() {
			sbft.castVote(verificationData.LeaderID)
		})

		// sbft.castVote(verificationData.LeaderID)
	}

}

func (sbft *SleepyBFT) castVote(LeaderID int) {
	voteData := struct {
		NodeID        int
		CurrentView   int
		EligibleNodes map[int]bool
	}{
		NodeID:        LeaderID,
		CurrentView:   sbft.State.CurrentView,
		EligibleNodes: sbft.EligibleNextRound,
	}

	voteContent, _ := json.Marshal(voteData)
	// voteHash := sha256.Sum256(voteContent)
	//voteSignature := ed25519.Sign(sbft.node.PrivateKey, voteContent)

	blsPrivateKey := getBLSPrivateKey(sbft.node.ID)

	var augScheme bls.AugSchemeMPL
	voteSignature := augScheme.Sign(blsPrivateKey, voteContent)
	sbft.Signatures = append(sbft.Signatures, voteSignature)
	sbft.NodeSignatures[sbft.node.ID] = voteSignature
	sbft.NodeMessages[sbft.node.ID] = voteContent

	voteMsg := Message{
		Type:      "vote",
		Content:   voteContent,
		Signature: voteSignature,
		// Signature: signatureBytes,
		SenderID: sbft.node.ID,
	}

	// time.AfterFunc(2*time.Second, func() {
	// 	sbft.BroadcastMessage(voteMsg)
	// 	fmt.Println("Node", sbft.node.ID, "cast vote for block with Leader ID", LeaderID)
	// })
	sbft.BroadcastMessage(voteMsg)
	fmt.Println("Node", sbft.node.ID, "cast vote for block with Leader ID", LeaderID)
	// fmt.Println("Node", sbft.node.ID, "EligibleNextRound:", sbft.EligibleNextRound)
	sbft.VoteSent = true
	for _, cachedMsg := range sbft.voteCache {
		sbft.HandleVote(cachedMsg) // 处理缓存的投票消息
	}
	sbft.voteCache = nil
}

func (sbft *SleepyBFT) HandleVote(msg Message) {
	if !sbft.VoteSent {
		sbft.voteCache = append(sbft.voteCache, msg)
		fmt.Println("Caching vote message from Node", msg.SenderID)
		return
	}

	blsPublickey := getBLSPublicKey(msg.SenderID)
	var augScheme bls.AugSchemeMPL
	if !augScheme.Verify(blsPublickey, msg.Content, msg.Signature) {
		fmt.Println("Invalid signature from Node", msg.SenderID)
		return
	}

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

	// sbft.mutex.Lock()
	for nodeID, isEligible := range voteData.EligibleNodes {
		if isEligible {
			sbft.ConfirmedEligibleNextRound[nodeID]++ // 增加对应节点的计数
		}
	}
	// sbft.mutex.Unlock()

	if voteData.CurrentView == sbft.State.CurrentView && voteData.NodeID == sbft.LeaderId {
		//fmt.Println("Node", sbft.node.ID, "received vote from Node", msg.SenderID, "for block with Leader ID", voteData.NodeID)

		// sbft.mutex.Lock()
		sbft.VotesCount[voteData.NodeID]++
		sbft.Signatures = append(sbft.Signatures, msg.Signature)
		sbft.NodeSignatures[msg.SenderID] = msg.Signature
		sbft.NodeMessages[msg.SenderID] = msg.Content
		count := sbft.VotesCount[sbft.LeaderId]
		alreadyConfirmed := sbft.ConfirmationSent
		// sbft.mutex.Unlock()

		if count > len(sbft.Nodes)*2/3 && !alreadyConfirmed {
			for id := range sbft.NodeSignatures {
				sbft.AggregatedNodes = append(sbft.AggregatedNodes, id)
			}

			aggregatedSignature, err := augScheme.Aggregate(sbft.Signatures...)
			if err != nil {
				fmt.Println("Error aggregating signatures:", err)
				return
			}

			sbft.AggregatedSignature = aggregatedSignature
			if !sbft.ConfirmationSent {

				time.AfterFunc(time.Second, func() {
					sbft.broadcastConfirmation(sbft.LeaderId)
				})

				// sbft.broadcastConfirmation(sbft.LeaderId)
			}

		}
	}

}

func (sbft *SleepyBFT) broadcastConfirmation(leaderID int) {
	msgContent, _ := json.Marshal(struct {
		LeaderID            int
		AggregatedSignature []byte
		NodeIDs             []int
	}{
		LeaderID:            leaderID,
		AggregatedSignature: sbft.AggregatedSignature,
		NodeIDs:             sbft.AggregatedNodes,
	})

	fmt.Println("Node", sbft.node.ID, "sending confirmation for block with Leader ID", leaderID, "with AggregatedNodes:", sbft.AggregatedNodes)

	for _, node := range sbft.Nodes {
		if node.ID != sbft.node.ID && sbft.FinalEligibleNextRound[node.ID] {
			sbft.SendMessage(node.Address, Message{
				Type:     "confirmation",
				Content:  msgContent,
				SenderID: sbft.node.ID,
			})
		}
	}
	sbft.ConfirmationSent = true
	for _, cachedMsg := range sbft.confirmationCache {
		sbft.HandleConfirmation(cachedMsg) // 处理缓存的确认消息
	}
	sbft.confirmationCache = nil // 清空缓存
}

// HandleConfirmation adapted for SleepyBFT (implementation needed)
func (sbft *SleepyBFT) HandleConfirmation(msg Message) {
	if sbft.State.SleepyNodes[msg.SenderID] {
		fmt.Println("Ignoring message from sleepy node", msg.SenderID)
		return
	}

	if !sbft.ConfirmationSent {
		sbft.confirmationCache = append(sbft.confirmationCache, msg)
		fmt.Println("Caching confirmation message from Node", msg.SenderID)
		return
	}

	var confirmationData struct {
		LeaderID            int
		AggregatedSignature []byte
		NodeIDs             []int
	}
	err := json.Unmarshal(msg.Content, &confirmationData)
	if err != nil {
		fmt.Println("Error unmarshalling confirmation data:", err)
		return
	}

	var pks [][]byte
	var messages [][]byte
	for _, nodeID := range sbft.AggregatedNodes {
		pks = append(pks, getBLSPublicKey(nodeID).Bytes())
		messages = append(messages, sbft.NodeMessages[nodeID])
	}
	var augScheme bls.AugSchemeMPL

	for nodeID, count := range sbft.ConfirmedEligibleNextRound {
		if count > len(sbft.Nodes)*2/3 {
			sbft.FinalEligibleNextRound[nodeID] = true
		} else {
			sbft.FinalEligibleNextRound[nodeID] = false
		}
	}

	if augScheme.AggregateVerify(pks, messages, sbft.AggregatedSignature) {
		sbft.confirmationList[confirmationData.LeaderID]++
		if (sbft.confirmationList[confirmationData.LeaderID] > len(sbft.Nodes)*2/3) && !sbft.ConfirmationReceived {
			fmt.Println("Node", sbft.node.ID, "received enough confirmation for LeaderID", confirmationData.LeaderID, "with NextRound EligibleNodes:", sbft.FinalEligibleNextRound)
			sbft.ConfirmationReceived = true
			sbft.State.CurrentView++

			sbft.selfProposalSent = false
			sbft.ConfirmationSent = false
			sbft.ConfirmationReceived = false
			sbft.ShareSent = false
			sbft.VoteSent = false

			for id := range sbft.VRFValues {
				delete(sbft.VRFValues, id)
			}

			for id := range sbft.Shares {
				delete(sbft.Shares, id)
			}

			for id := range sbft.ShareIndex {
				delete(sbft.ShareIndex, id)
			}

			for id := range sbft.Block {
				delete(sbft.Block, id)
			}

			for id := range sbft.NextRoundCommitments {
				delete(sbft.NextRoundCommitments, id)
			}

			for id := range sbft.NextRoundCommitCount {
				sbft.NextRoundCommitCount[id] = 0
			}

			for id := range sbft.EligibleNextRound {
				sbft.EligibleNextRound[id] = false
			}

			for id := range sbft.ConfirmedEligibleNextRound {
				sbft.ConfirmedEligibleNextRound[id] = 0
			}

			for id := range sbft.testLeaderShare {
				delete(sbft.testLeaderShare, id)
			}

			for id := range sbft.testShare {
				delete(sbft.testShare, id)
			}

			for id := range sbft.NodeSignatures {
				delete(sbft.NodeSignatures, id)
			}

			for id := range sbft.NodeMessages {
				delete(sbft.NodeMessages, id)
			}

			sbft.Signatures = sbft.Signatures[:0]
			sbft.AggregatedSignature = nil
			sbft.AggregatedNodes = sbft.AggregatedNodes[:0]

			for id := range sbft.VotesCount {
				sbft.VotesCount[id] = 0
			}

			for id := range sbft.confirmationList {
				sbft.confirmationList[id] = 0
			}

			for node := range sbft.ProposalSent {
				sbft.ProposalSent[node] = false
			}

			time.AfterFunc(2*time.Second, func() {
				go sbft.SendProposal()
			})
		}
	}
}

func (sbft *SleepyBFT) HandleAwake(msg Message) {
	fmt.Println("Node", msg.SenderID, "is awake")
}
