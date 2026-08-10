// session_ws.go implements probe.Session over a raw RFC 6455 WebSocket
// connection using only the standard library — no gorilla/websocket or
// similar dependency, matching the project's zero-dependency ethos. This
// transport isn't part of the official MCP spec, but some community
// gateways/proxies speak JSON-RPC over a plain WebSocket anyway (see
// internal/discovery/websocket_detector.go, which only confirms the
// upgrade handshake for detection purposes — this file is what lets a
// discovered WebSocket target actually be enumerated).
package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/probe/common"
)

const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

// WSSession is the WebSocket implementation of probe.Session. A WebSocket
// is a persistent, full-duplex connection rather than one-request-per-call
// like HTTP, so — same shape as SSESession — a background reader
// dispatches inbound frames to whichever Do() call is waiting on that
// frame's JSON-RPC id.
type WSSession struct {
	targetURL string
	conn      net.Conn
	writeMu   sync.Mutex

	mu      sync.Mutex
	reqID   int
	pending map[int]chan *probe.RawResult
}

// NewWSSession dials and completes the WebSocket upgrade immediately
// (unlike SSESession's lazy connect, a WS handshake is a single fast round
// trip, so there's no benefit to deferring it) and starts the background
// frame reader.
func NewWSSession(targetURL, authHeader string, timeout time.Duration) (*WSSession, error) {
	dialer := &net.Dialer{Timeout: timeout}
	var headers map[string]string
	if authHeader != "" {
		headers = map[string]string{"Authorization": authHeader}
	}
	conn, _, err := common.DialWebSocket(dialer, targetURL, headers)
	if err != nil {
		return nil, fmt.Errorf("websocket handshake: %w", err)
	}
	s := &WSSession{
		targetURL: targetURL,
		conn:      conn,
		pending:   make(map[int]chan *probe.RawResult),
	}
	go s.runReader()
	return s, nil
}

func (s *WSSession) TargetURL() string { return s.targetURL }

// Do sends one JSON-RPC request as a text frame and waits for a response
// frame carrying the same id. Per-request options that only make sense for
// a fresh HTTP request (WithNoAuth, extra per-call headers) don't apply to
// an already-established WebSocket connection — auth is a handshake-time
// concept here, set once in NewWSSession — so ReqOptions are accepted for
// interface compatibility but have no effect.
func (s *WSSession) Do(ctx context.Context, method string, params any, opts ...probe.ReqOption) (*probe.RawResult, error) {
	s.mu.Lock()
	s.reqID++
	id := s.reqID
	respCh := make(chan *probe.RawResult, 1)
	s.pending[id] = respCh
	s.mu.Unlock()

	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, fmt.Errorf("encode request: %w", err)
	}

	start := time.Now()
	if err := s.writeFrame(wsOpText, body); err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return &probe.RawResult{Err: err}, err
	}

	select {
	case raw := <-respCh:
		if raw.Err != nil {
			return raw, raw.Err
		}
		raw.Latency = time.Since(start)
		return raw, nil
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (s *WSSession) runReader() {
	r := bufio.NewReader(s.conn)
	var accOpcode byte
	var acc []byte

	for {
		fin, opcode, payload, err := readWSFrame(r)
		if err != nil {
			s.failAll(err)
			return
		}
		switch opcode {
		case wsOpPing:
			_ = s.writeFrame(wsOpPong, payload)
		case wsOpPong:
			// no-op
		case wsOpClose:
			_ = s.writeFrame(wsOpClose, nil)
			s.failAll(io.EOF)
			return
		case wsOpContinuation:
			acc = append(acc, payload...)
			if fin {
				s.handleMessage(accOpcode, acc)
				acc = nil
			}
		default: // text or binary: start (or all) of a message
			if !fin {
				accOpcode = opcode
				acc = append([]byte{}, payload...)
			} else {
				s.handleMessage(opcode, payload)
			}
		}
	}
}

func (s *WSSession) handleMessage(opcode byte, payload []byte) {
	if opcode != wsOpText && opcode != wsOpBinary {
		return
	}
	var envelope struct {
		ID *int `json:"id"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.ID == nil {
		return // notification or malformed frame — this session only speaks request/response
	}
	s.mu.Lock()
	ch, ok := s.pending[*envelope.ID]
	if ok {
		delete(s.pending, *envelope.ID)
	}
	s.mu.Unlock()
	if ok {
		ch <- &probe.RawResult{StatusCode: 200, Body: payload}
	}
}

func (s *WSSession) failAll(err error) {
	s.mu.Lock()
	for id, ch := range s.pending {
		ch <- &probe.RawResult{Err: err}
		delete(s.pending, id)
	}
	s.mu.Unlock()
}

// writeFrame sends one unfragmented client frame. RFC 6455 requires every
// client-to-server frame to be masked; readWSFrame below tolerates but
// doesn't require masking on the read side, since servers must NOT mask
// but some non-conformant ones might.
func (s *WSSession) writeFrame(opcode byte, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var header []byte
	header = append(header, 0x80|opcode) // FIN=1, no RSV bits, opcode

	maskKey := make([]byte, 4)
	if _, err := rand.Read(maskKey); err != nil {
		return err
	}

	n := len(payload)
	switch {
	case n < 126:
		header = append(header, 0x80|byte(n))
	case n <= 0xFFFF:
		header = append(header, 0x80|126)
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(n))
		header = append(header, lenBuf...)
	default:
		header = append(header, 0x80|127)
		lenBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBuf, uint64(n))
		header = append(header, lenBuf...)
	}
	header = append(header, maskKey...)

	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ maskKey[i%4]
	}

	if _, err := s.conn.Write(header); err != nil {
		return err
	}
	_, err := s.conn.Write(masked)
	return err
}

// readWSFrame reads exactly one frame (fragment) from r, unmasking the
// payload if the frame is masked (servers shouldn't mask, but this
// tolerates it rather than erroring).
func readWSFrame(r *bufio.Reader) (fin bool, opcode byte, payload []byte, err error) {
	head := make([]byte, 2)
	if _, err = io.ReadFull(r, head); err != nil {
		return false, 0, nil, err
	}
	fin = head[0]&0x80 != 0
	opcode = head[0] & 0x0F
	masked := head[1]&0x80 != 0
	length := uint64(head[1] & 0x7F)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(r, ext); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext)
	}
	if length > 4<<20 { // 4MB cap, same discipline as the HTTP sessions
		return false, 0, nil, fmt.Errorf("websocket frame too large (%d bytes)", length)
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err = io.ReadFull(r, maskKey); err != nil {
			return false, 0, nil, err
		}
	}

	payload = make([]byte, length)
	if _, err = io.ReadFull(r, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return fin, opcode, payload, nil
}
