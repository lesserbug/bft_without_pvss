package main

import (
	"log"

	"time"
)

func main() {
	// nodes := []Node{
	// 	{ID: 1, Address: "localhost:8001", Nodes: []Node{}, VRFValues: make(map[int][]byte)},
	// 	{ID: 2, Address: "localhost:8002", Nodes: []Node{}, VRFValues: make(map[int][]byte)},
	// 	{ID: 3, Address: "localhost:8003", Nodes: []Node{}, VRFValues: make(map[int][]byte)},
	// }

	// generateAndSaveKeys(1)
	// generateAndSaveKeys(2)
	// generateAndSaveKeys(3)
	// generateAndSavePVSSKeys(1)
	// generateAndSavePVSSKeys(2)
	// generateAndSavePVSSKeys(3)
	// generateAndSaveBLSKeys(1)
	// generateAndSaveBLSKeys(2)
	// generateAndSaveBLSKeys(3)

	// for i := range nodes {
	// 	for j := range nodes {
	// 		if i != j {
	// 			nodes[i].Nodes = append(nodes[i].Nodes, nodes[j])
	// 		}
	// 	}
	// }

	// // Start listening on each node in a separate goroutine
	// for i := range nodes {
	// 	go func(n *Node) {
	// 		n.Listen()
	// 	}(&nodes[i])
	// }

	// // Allow some time for all nodes to start listening
	// time.Sleep(2 * time.Second)

	// // Simultaneously start the proposal phase for each node
	// for i := range nodes {
	// 	go func(n *Node) {
	// 		n.SendProposal()
	// 	}(&nodes[i])
	// }

	// log.Println("Simulation running. Press CTRL+C to stop.")
	// select {} // Keep the program running indefinitely to observe node interactions
	sleepyBFTInstances := []*SleepyBFT{
		NewSleepyBFT(1, "localhost:8001"),
		NewSleepyBFT(2, "localhost:8002"),
		NewSleepyBFT(3, "localhost:8003"),
	}

	// // Link the nodes with each other
	// for i := range sleepyBFTInstances {
	// 	for j := range sleepyBFTInstances {
	// 		if i != j {
	// 			sleepyBFTInstances[i].Nodes = append(sleepyBFTInstances[i].Nodes, sleepyBFTInstances[j].node)
	// 		}
	// 	}
	// }

	// Initialize PVSS public keys for each node
	for _, instance := range sleepyBFTInstances {
		pvssPublicKey := getPVSSPublicKey(instance.node.ID)
		instance.PVSSNodes = append(instance.PVSSNodes, PVSSNode{Index: instance.node.ID, PubKey: pvssPublicKey})
	}
	// Link the nodes with each other
	for i, sbft := range sleepyBFTInstances {
		for j, otherSbft := range sleepyBFTInstances {
			if i != j {
				sbft.Nodes = append(sbft.Nodes, otherSbft.node)
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
	time.Sleep(2 * time.Second)

	// Simultaneously start the proposal phase for each node
	for _, sbft := range sleepyBFTInstances {
		go sbft.SendProposal()
	}

	log.Println("Simulation running. Press CTRL+C to stop.")
	select {} // Keep the program running indefinitely to observe node interactions

}
