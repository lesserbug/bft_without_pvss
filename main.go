package main

import (
	"log"

	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"
)

func main() {

	// for i := range make([]int, 31) {
	// 	generateAndSaveKeys(i + 10)
	// }

	totalNodesPerInstance := 10
	totalRounds := 10
	maliciousNodeCount := 1

	// 创建CSV文件用于记录实验数据
	file, err := os.Create("experiment_results_node1.csv")
	if err != nil {
		log.Fatal("Cannot create file", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Round", "NodeID", "LeaderID", "ChainLength", "ForkCount"})

	dataChan := make(chan RoundData, totalNodesPerInstance*totalRounds)

	ip1 := "0.0.0.0:" // 使用 0.0.0.0 允许从任何 IP 访问
	sleepyBFTInstances := createInstances(totalNodesPerInstance, maliciousNodeCount, dataChan, totalRounds, ip1)

	// 创建其他实例的节点信息
	ip2 := "13.210.47.22:"
	nodes2 := createOtherInstanceNodes(11, ip2)

	for _, sbft := range sleepyBFTInstances {
		for _, sbft2 := range sleepyBFTInstances {
			if sbft.node.ID != sbft2.node.ID {
				sbft.Nodes = append(sbft.Nodes, sbft2.node)
			}
		}
		sbft.Nodes = append(sbft.Nodes, nodes2...)

		// Initialize ProposalSent for each node
		for _, node := range sbft.Nodes {
			sbft.ProposalSent[node.ID] = false
		}
	}

	// Initialize ProposalSent for each node
	for _, sbft := range sleepyBFTInstances {
		for _, node := range sbft.Nodes {
			sbft.ProposalSent[node.ID] = false
		}
		sbft.ProposalSent[sbft.node.ID] = false
	}

	// Start listening on each node in a separate goroutine
	for _, sbft := range sleepyBFTInstances {
		go sbft.Listen()
	}

	// Allow some time for all nodes to start listening
	time.Sleep(2 * time.Second)

	for _, sbft := range sleepyBFTInstances {
		go sbft.SendProposal()
	}

	waitForAllNodesToComplete(sleepyBFTInstances, totalRounds)

	close(dataChan)

	// Collect and write all data
	for data := range dataChan {
		writer.Write([]string{
			strconv.Itoa(data.Round),
			strconv.Itoa(data.NodeID),
			strconv.Itoa(data.LeaderID),
			strconv.Itoa(data.ChainLength),
			strconv.Itoa(data.ForkCount),
		})
	}

	writer.Flush()

	fmt.Println("Experiment completed. Results written to experiment_results.csv")

}

func createInstances(totalNodes, maliciousNodes int, dataChan chan RoundData, targetRound int, ip string) []*SleepyBFT {
	instances := make([]*SleepyBFT, totalNodes)
	for i := 0; i < totalNodes; i++ {
		isMalicious := i < maliciousNodes
		instances[i] = NewSleepyBFT(i+1, fmt.Sprintf("%s%d", ip, 8001+i), isMalicious, dataChan, targetRound)
	}
	return instances
}

func createOtherInstanceNodes(startID int, ip string) []Node {
	nodes := make([]Node, 10)
	for i := 0; i < 10; i++ {
		nodes[i] = Node{
			ID:      startID + i,
			Address: fmt.Sprintf("%s%d", ip, 8001+i),
		}
	}
	return nodes
}

func waitForAllNodesToComplete(instances []*SleepyBFT, targetRound int) {
	allCompleted := false
	for !allCompleted {
		allCompleted = true
		for _, sbft := range instances {
			if sbft.currentRound < targetRound {
				allCompleted = false
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}
