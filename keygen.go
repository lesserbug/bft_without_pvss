package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	bls "github.com/chuwt/chia-bls-go"

	"github.com/torusresearch/pvss/common"
	"github.com/torusresearch/pvss/secp256k1"
)

// Generate and save keys for a given node ID
func generateAndSaveKeys(nodeID int) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}

	publicKeyPath := fmt.Sprintf("Keys/Node%d/Node%d_ED25519_PUB", nodeID, nodeID)
	privateKeyPath := fmt.Sprintf("Keys/Node%d/Node%d_ED25519_PRIV", nodeID, nodeID)

	// Ensure the directory exists
	os.MkdirAll(fmt.Sprintf("Keys/Node%d", nodeID), 0700)

	// Write public key
	if err := ioutil.WriteFile(publicKeyPath, publicKey, 0644); err != nil {
		fmt.Println("Error saving public key:", err)
	}

	// Write private key
	if err := ioutil.WriteFile(privateKeyPath, privateKey, 0644); err != nil {
		fmt.Println("Error saving private key:", err)
	}
}

// Generate and save PVSS keys for a given node ID
func generateAndSavePVSSKeys(nodeID int) {
	// 生成私钥
	privateKey := RandomBigInt() // 使用pvss提供的RandomBigInt()生成随机私钥

	// 使用私钥生成公钥
	publicKeyX, publicKeyY := secp256k1.Curve.ScalarBaseMult(privateKey.Bytes()) // ScalarBaseMult根据私钥生成公钥
	publicKey := common.Point{X: *publicKeyX, Y: *publicKeyY}

	publicKeyPath := fmt.Sprintf("Keys/Node%d/Node%d_PVSS_PUB", nodeID, nodeID)
	privateKeyPath := fmt.Sprintf("Keys/Node%d/Node%d_PVSS_PRIV", nodeID, nodeID)

	// 确保密钥存储目录存在
	os.MkdirAll(fmt.Sprintf("Keys/Node%d", nodeID), 0700)

	// 序列化和保存公钥
	publicKeyBytes := append(publicKey.X.Bytes(), publicKey.Y.Bytes()...) // 公钥为X和Y坐标的组合
	if err := ioutil.WriteFile(publicKeyPath, publicKeyBytes, 0644); err != nil {
		fmt.Printf("Error saving PVSS public key for node %d: %v\n", nodeID, err)
	}

	// 序列化和保存私钥
	if err := ioutil.WriteFile(privateKeyPath, privateKey.Bytes(), 0644); err != nil {
		fmt.Printf("Error saving PVSS private key for node %d: %v\n", nodeID, err)
	}
}

// Generate and save BLS keys for a given node ID
func generateAndSaveBLSKeys(nodeID int) {
	// Generating a private key from a random seed
	seed := make([]byte, 32) // A random 32-byte seed, use a secure RNG in production
	privateKey := bls.KeyGen(seed)

	// Getting the corresponding public key
	publicKey := privateKey.GetPublicKey()

	publicKeyPath := fmt.Sprintf("Keys/Node%d/Node%d_BLS_PUB", nodeID, nodeID)
	privateKeyPath := fmt.Sprintf("Keys/Node%d/Node%d_BLS_PRIV", nodeID, nodeID)

	// Ensure the directory exists
	os.MkdirAll(fmt.Sprintf("Keys/Node%d", nodeID), 0700)

	// Write public key
	if err := ioutil.WriteFile(publicKeyPath, []byte(hex.EncodeToString(publicKey.Bytes())), 0644); err != nil {
		fmt.Println("Error saving public key:", err)
	}

	// Write private key
	if err := ioutil.WriteFile(privateKeyPath, []byte(hex.EncodeToString(privateKey.Bytes())), 0644); err != nil {
		fmt.Println("Error saving private key:", err)
	}
}
