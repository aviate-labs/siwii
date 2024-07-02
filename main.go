package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/aviate-labs/agent-go/certification"
	ii "github.com/aviate-labs/agent-go/certification/ii"
	"github.com/aviate-labs/agent-go/ic"
	"github.com/aviate-labs/agent-go/principal"
)

var challenge [32]byte

func init() {
	if _, err := rand.Read(challenge[:]); err != nil {
		panic(err)
	}
}

func main() {
	http.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		payload, err := json.Marshal(map[string]any{
			"challenge": base64.StdEncoding.EncodeToString(challenge[:]),
		})
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	})
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodPost:
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var m struct {
			Challenge  string `json:"challenge"`
			Delegation struct {
				Kind          string                `json:"kind"`
				Delegations   []ii.SignedDelegation `json:"delegations"`
				UserPublicKey ii.HexString          `json:"userPublicKey"`
				AuthnMethod   string                `json:"authnMethod"`
			} `json:"delegation"`
		}
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		dc := ii.DelegationChain{
			Delegations: m.Delegation.Delegations,
			PublicKey:   m.Delegation.UserPublicKey,
		}
		rawChallenge, _ := base64.StdEncoding.DecodeString(m.Challenge)
		rootKey, _ := hex.DecodeString(certification.RootKey)
		if err := dc.VerifyChallenge(
			rawChallenge,
			uint64(time.Now().UnixNano()),
			ic.IDENTITY_PRINCIPAL,
			rootKey,
		); err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		payload, err := json.Marshal(map[string]any{
			"principal": principal.NewSelfAuthenticating([]byte(m.Delegation.UserPublicKey)).String(),
		})
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(payload)
	})
	_ = http.ListenAndServe(":8123", nil)
}
