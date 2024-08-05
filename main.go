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

	// 131.170.239.18
	sleepyBFTInstances := []*SleepyBFT{
		// NewSleepyBFT(1, "localhost:8001"),
		// NewSleepyBFT(2, "localhost:8002"),
		// NewSleepyBFT(3, "localhost:8003"),
		NewSleepyBFT(1, "0.0.0.0:8001"),
		NewSleepyBFT(2, "0.0.0.0:8002"),
		NewSleepyBFT(3, "0.0.0.0:8003"),
	}

	// Initialize PVSS public keys for each node
	for _, instance := range sleepyBFTInstances {
		pvssPublicKey := getPVSSPublicKey(instance.node.ID)
		instance.PVSSNodes = append(instance.PVSSNodes, PVSSNode{Index: instance.node.ID, PubKey: pvssPublicKey})
	}

	sleepyBFTInstances[0].Nodes = append(sleepyBFTInstances[0].Nodes, Node{ID: 2, Address: "3.107.58.63:8002"})    // EC2 Node 1 to EC2 Node 2
	sleepyBFTInstances[0].Nodes = append(sleepyBFTInstances[0].Nodes, Node{ID: 3, Address: "131.170.239.18:8003"}) // EC2 Node 1 to Local Node

	sleepyBFTInstances[1].Nodes = append(sleepyBFTInstances[1].Nodes, Node{ID: 1, Address: "3.107.58.63:8001"})    // EC2 Node 2 to EC2 Node 1
	sleepyBFTInstances[1].Nodes = append(sleepyBFTInstances[1].Nodes, Node{ID: 3, Address: "131.170.239.18:8003"}) // EC2 Node 2 to Local Node

	sleepyBFTInstances[2].Nodes = append(sleepyBFTInstances[2].Nodes, Node{ID: 1, Address: "3.107.58.63:8001"}) // Local Node to EC2 Node 1
	sleepyBFTInstances[2].Nodes = append(sleepyBFTInstances[2].Nodes, Node{ID: 2, Address: "3.107.58.63:8002"}) // Local Node to EC2 Node 2

	// Link the nodes with each other
	for i, sbft := range sleepyBFTInstances {
		for j, otherSbft := range sleepyBFTInstances {
			if i != j {
				// sbft.Nodes = append(sbft.Nodes, otherSbft.node)
				// Add other node's PVSS node information as well
				sbft.PVSSNodes = append(sbft.PVSSNodes, PVSSNode{Index: otherSbft.node.ID, PubKey: otherSbft.PVSSNodes[0].PubKey})
			}
		}
	}

	// Initialize FinalEligibleNextRound for each node
	for _, sbft := range sleepyBFTInstances {
		for _, node := range sbft.Nodes {
			sbft.FinalEligibleNextRound[node.ID] = true
			sbft.ProposalSent[node.ID] = false
		}
		sbft.FinalEligibleNextRound[sbft.node.ID] = true // Also mark self as eligible
		sbft.ProposalSent[sbft.node.ID] = false
	}

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
