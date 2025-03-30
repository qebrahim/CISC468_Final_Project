package network

import (
	"encoding/json"
	"net"
)

type Message struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

func SendMessage(conn net.Conn, msg Message) error {
	encoder := json.NewEncoder(conn)
	return encoder.Encode(msg)
}

func ReceiveMessage(conn net.Conn) (Message, error) {
	var msg Message
	decoder := json.NewDecoder(conn)
	err := decoder.Decode(&msg)
	return msg, err
}
