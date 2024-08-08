package main

import (
	"log"

	"time"
)

func main() {
	// generateAndSaveKeys(1)
	// generateAndSaveKeys(2)
	// generateAndSaveKeys(3)
	// generateAndSavePVSSKeys(1)
	// generateAndSavePVSSKeys(2)
	// generateAndSavePVSSKeys(3)
	// generateAndSaveBLSKeys(1)
	// generateAndSaveBLSKeys(2)
	// generateAndSaveBLSKeys(3)

	sleepyBFTInstances := []*SleepyBFT{
		NewSleepyBFT(3, "0.0.0.0:8003"),
	}

	sleepyBFTInstances[0].Nodes = append(sleepyBFTInstances[0].Nodes, Node{ID: 1, Address: "3.104.74.7:8001"})
	sleepyBFTInstances[0].Nodes = append(sleepyBFTInstances[0].Nodes, Node{ID: 2, Address: "3.104.74.7:8002"})
	sleepyBFTInstances[0].PVSSNodes = append(sleepyBFTInstances[0].PVSSNodes, PVSSNode{Index: 1, PubKey: getPVSSPublicKey(1)})
	sleepyBFTInstances[0].PVSSNodes = append(sleepyBFTInstances[0].PVSSNodes, PVSSNode{Index: 2, PubKey: getPVSSPublicKey(2)})
	sleepyBFTInstances[0].PVSSNodes = append(sleepyBFTInstances[0].PVSSNodes, PVSSNode{Index: 3, PubKey: getPVSSPublicKey(3)})
	sleepyBFTInstances[0].FinalEligibleNextRound[1] = true
	sleepyBFTInstances[0].FinalEligibleNextRound[2] = true
	sleepyBFTInstances[0].FinalEligibleNextRound[3] = true
	sleepyBFTInstances[0].ProposalSent[1] = false
	sleepyBFTInstances[0].ProposalSent[2] = false
	sleepyBFTInstances[0].ProposalSent[3] = false

	// // Initialize PVSS public keys for each node
	// for _, instance := range sleepyBFTInstances {
	// 	pvssPublicKey := getPVSSPublicKey(instance.node.ID)
	// 	instance.PVSSNodes = append(instance.PVSSNodes, PVSSNode{Index: instance.node.ID, PubKey: pvssPublicKey})
	// }

	// // Link the nodes with each other
	// for i, sbft := range sleepyBFTInstances {
	// 	for j, otherSbft := range sleepyBFTInstances {
	// 		if i != j {
	// 			// sbft.Nodes = append(sbft.Nodes, otherSbft.node)
	// 			// Add other node's PVSS node information as well
	// 			sbft.PVSSNodes = append(sbft.PVSSNodes, PVSSNode{Index: otherSbft.node.ID, PubKey: otherSbft.PVSSNodes[0].PubKey})
	// 		}
	// 	}
	// }

	// // Initialize FinalEligibleNextRound for each node
	// for _, sbft := range sleepyBFTInstances {
	// 	for _, node := range sbft.Nodes {
	// 		sbft.FinalEligibleNextRound[node.ID] = true
	// 		sbft.ProposalSent[node.ID] = false
	// 	}
	// 	sbft.FinalEligibleNextRound[sbft.node.ID] = true // Also mark self as eligible
	// 	sbft.ProposalSent[sbft.node.ID] = false
	// }

	// Start listening on each node in a separate goroutine
	for _, sbft := range sleepyBFTInstances {
		go sbft.Listen()
	}

	// Allow some time for all nodes to start listening
	time.Sleep(5 * time.Second)

	// Simultaneously start the proposal phase for each node
	for _, sbft := range sleepyBFTInstances {
		go sbft.SendProposal()
	}

	log.Println("Simulation running. Press CTRL+C to stop.")
	select {} // Keep the program running indefinitely to observe node interactions

}
