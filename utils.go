package main

import (
	"math/big"

	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"

	"crypto/ed25519"

	bls "github.com/chuwt/chia-bls-go"

	"github.com/torusresearch/pvss/common"
	"github.com/torusresearch/pvss/secp256k1"
)

func getPubKey(nodeID int) ed25519.PublicKey {
	keyPath := fmt.Sprintf("Keys/Node%d/Node%d_ED25519_PUB", nodeID, nodeID)
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Panic("Failed to read public key:", err)
	}
	return key
}

func getPrivKey(nodeID int) ed25519.PrivateKey {
	keyPath := fmt.Sprintf("Keys/Node%d/Node%d_ED25519_PRIV", nodeID, nodeID)
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Panic("Failed to read private key:", err)
	}
	return key
}

func getPVSSPublicKey(nodeID int) common.Point {
	pubKeyPath := fmt.Sprintf("Keys/Node%d/Node%d_PVSS_PUB", nodeID, nodeID)
	pubKeyData, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		log.Panicf("Failed to read PVSS public key for Node %d: %v", nodeID, err)
	}

	x := new(big.Int).SetBytes(pubKeyData[:32]) // 假设公钥是64字节，前32字节为X，后32字节为Y
	y := new(big.Int).SetBytes(pubKeyData[32:])
	return common.Point{X: *x, Y: *y}
}

func getBLSPrivateKey(nodeID int) bls.PrivateKey {
	keyPath := fmt.Sprintf("Keys/Node%d/Node%d_BLS_PRIV", nodeID, nodeID)
	keyHex, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Panic("Failed to read private key:", err)
	}
	privateKey, err := bls.KeyFromHexString(string(keyHex))
	if err != nil {
		log.Panic("Failed to parse private key:", err)
	}
	return privateKey
}

func getBLSPublicKey(nodeID int) bls.PublicKey {
	keyPath := fmt.Sprintf("Keys/Node%d/Node%d_BLS_PUB", nodeID, nodeID)
	keyHex, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Panic("Failed to read public key:", err)
	}
	keyBytes, err := hex.DecodeString(string(keyHex))
	if err != nil {
		log.Panic("Failed to decode public key from hex:", err)
	}
	publicKey, err := bls.NewPublicKey(keyBytes)
	if err != nil {
		log.Panic("Failed to parse public key:", err)
	}
	return publicKey
}

func verifyShareUsingCommits(share common.PrimaryShare, commits []common.Point) bool {
	x := big.NewInt(int64(share.Index))

	// 计算g^{P(x)} = Π (g^{a_j})^{x^j}，其中a_j是承诺的系数
	computedPointX, computedPointY := new(big.Int), new(big.Int)

	for j, commit := range commits {
		// 计算x^j
		exp := new(big.Int).Exp(x, big.NewInt(int64(j)), nil)
		// commit.X, commit.Y是承诺点g^{a_j}
		// g^{a_j * x^j} = g^{a_j}^{x^j}
		tempX, tempY := secp256k1.Curve.ScalarMult(&commit.X, &commit.Y, exp.Bytes())

		if j == 0 {
			computedPointX, computedPointY = tempX, tempY
		} else {
			// 椭圆曲线上点的加法
			computedPointX, computedPointY = secp256k1.Curve.Add(computedPointX, computedPointY, tempX, tempY)
		}
	}

	// 计算g^{s_i}
	gSiX, gSiY := secp256k1.Curve.ScalarBaseMult(share.Value.Bytes())

	// 比较计算出的点g^{P(x)}和g^{s_i}
	return computedPointX.Cmp(gSiX) == 0 && computedPointY.Cmp(gSiY) == 0
}

func deserializeCommitments(commitsData map[int]Commitment) map[int]common.Point {
	commits := make(map[int]common.Point)
	for i, data := range commitsData {
		x := new(big.Int).SetBytes(data.X)
		y := new(big.Int).SetBytes(data.Y)
		commits[i] = common.Point{X: *x, Y: *y}
	}
	return commits
}

func convertCommitsMapToList(commitsMap map[int]common.Point) *[]common.Point {
	var commitsList []common.Point
	// 假设map的键是按节点索引顺序来的
	numCommits := len(commitsMap)
	commitsList = make([]common.Point, numCommits)
	for i := 0; i < numCommits; i++ {
		commitsList[i] = commitsMap[i]
	}
	return &commitsList
}

func (sbft *SleepyBFT) determineLeader() int {
	minVRF := []byte{255, 255, 255, 255}
	leaderID := -1

	for id, vrfValue := range sbft.VRFValues {
		if bytes.Compare(vrfValue, minVRF) < 0 {
			minVRF = vrfValue
			leaderID = id
		}
	}

	return leaderID
}
