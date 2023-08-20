package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"github.com/bytemare/voprf"
)

const (
	// This is just a mock user ID for demonstration purposes
	hardcodedID    = "12345"
)

var secretKeyForID = map[string][]byte{
	// This is just a mock key for demonstration purposes
	hardcodedID: []byte("some(NotSo)RandomHardcodedSecretKeyForThisID"), 
}

func evaluateOPRF(blindedInput []byte, id string) []byte {
	// Initialize the OPRF with the desired cipher suite.
	oprfIdentifier := voprf.Ristretto255Sha512
	// retrieve the secret key associated with the requested user ID
	secretKey := secretKeyForID[id]
	// Initialized the OPRF server instance with the ID-associated secret key
	server, err := oprfIdentifier.Server(voprf.OPRF, secretKey)
	if err != nil {
		return nil
	}

	// Evaluate the blinded input
	blindedOutput := server.Evaluate(blindedInput)

	// Return the evaluated (still blinded) element.
	return blindedOutput
}

func handleRequest(c *gin.Context) {
	id := c.Query("id")
	input := c.Query("input")

	if _, exists := secretKeyForID[id]; !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	// Evaluate the blinded input
	blindedOutput := evaluateOPRF(blindedInput, id)

	// sending back the blinded output.
	// the client will unblind this output to get the final result.
	c.JSON(http.StatusOK, gin.H{
		"id":     id,
		"input":  input,
		"output": string(blindedOutput),
	})
}

func main() {
	r := gin.Default()
	r.GET("/oprf", handleRequest)
	r.Run() // By default, it listens on :8080
}
