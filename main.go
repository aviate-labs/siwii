package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
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
				Kind        string `json:"kind"`
				Delegations []struct {
					Delegation struct {
						PubKey     string `json:"pubkey"`
						Expiration string `json:"expiration"`
					}
					Signature string `json:"signature"`
				} `json:"delegations"`
				UserPublicKey string `json:"userPublicKey"`
				AuthnMethod   string `json:"authnMethod"`
			} `json:"delegation"`
		}
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		_ = m // TODO:validate delegation and signature
	})
	_ = http.ListenAndServe(":8123", nil)
}
