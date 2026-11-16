// Package queue buffers sealed batches between the batcher and the HTTPS
// senders. With a directory configured, every batch is fsynced to disk before
// it is acknowledged to the batcher, so a FlowTrim restart or an NG-SIEM
// outage does not lose data (until the size cap is hit).
package queue

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Batch is one HEC request body.
type Batch struct {
	ID         uint64
	Data       []byte
	Events     int
	Compressed bool
}

// Overflow policies.
const (
	DropOldest = "drop_oldest"
	Block      = "block"
)

// Queue is a FIFO of batches with an optional disk backing.
type Queue struct {
	mu       sync.Mutex
	cond     *sync.Cond
	dir      string
	maxBytes int64
	overflow string

	nextID   uint64
	pending  []meta // FIFO, not in flight
	mem      map[uint64][]byte
	inflight map[uint64]meta
	bytes    int64
	closed   bool

	OnDrop func(Batch) // called when a batch is evicted by drop_oldest
}

type meta struct {
	id         uint64
	size       int64
	events     int
	compressed bool
}

// ErrClosed is returned after Close.
var ErrClosed = errors.New("queue closed")

// New opens a queue. dir == "" means memory only.
func New(dir string, maxBytes int64, overflow string) (*Queue, error) {
	q := &Queue{dir: dir, maxBytes: maxBytes, overflow: overflow, mem: map[uint64][]byte{}, inflight: map[uint64]meta{}, nextID: 1}
	q.cond = sync.NewCond(&q.mu)
	if dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Join(dir, "dead"), 0o750); err != nil {
			return nil, err
		}
		if err := q.recover(); err != nil {
			return nil, err
		}
	}
	return q, nil
}

// file name: <id>.<events>.<g|r>.batch
func (q *Queue) path(m meta) string {
	c := "r"
	if m.compressed {
		c = "g"
	}
	return filepath.Join(q.dir, fmt.Sprintf("%020d.%d.%s.batch", m.id, m.events, c))
}

func (q *Queue) recover() error {
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasSuffix(n, ".tmp") {
			_ = os.Remove(filepath.Join(q.dir, n))
			continue
		}
		if !strings.HasSuffix(n, ".batch") {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(n, ".batch"), ".")
		if len(parts) != 3 {
			continue
		}
		id, err1 := strconv.ParseUint(parts[0], 10, 64)
		ev, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		m := meta{id: id, size: info.Size(), events: ev, compressed: parts[2] == "g"}
		q.pending = append(q.pending, m)
		q.bytes += m.size
		if id >= q.nextID {
			q.nextID = id + 1
		}
	}
	sort.Slice(q.pending, func(i, j int) bool { return q.pending[i].id < q.pending[j].id })
	return nil
}

// Recovered returns how many batches were found on disk at startup.
func (q *Queue) Len() (batches int, bytes int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending) + len(q.inflight), q.bytes
}

// Put appends a batch. It applies the overflow policy when over capacity.
func (q *Queue) Put(data []byte, events int, compressed bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	size := int64(len(data))
	for q.bytes+size > q.maxBytes && !q.closed {
		if q.overflow == Block || len(q.pending) == 0 {
			if len(q.pending) == 0 && len(q.inflight) == 0 {
				break // a single batch larger than the cap: accept it
			}
			q.cond.Wait()
			continue
		}
		old := q.pending[0]
		q.pending = q.pending[1:]
		var od []byte
		if q.dir != "" {
			_ = os.Remove(q.path(old))
		} else {
			od = q.mem[old.id]
			delete(q.mem, old.id)
		}
		q.bytes -= old.size
		if q.OnDrop != nil {
			q.OnDrop(Batch{ID: old.id, Data: od, Events: old.events, Compressed: old.compressed})
		}
	}
	if q.closed {
		return ErrClosed
	}
	m := meta{id: q.nextID, size: size, events: events, compressed: compressed}
	q.nextID++
	if q.dir != "" {
		p := q.path(m)
		tmp := p + ".tmp"
		if err := writeSync(tmp, data); err != nil {
			return err
		}
		if err := os.Rename(tmp, p); err != nil {
			return err
		}
	} else {
		q.mem[m.id] = data
	}
	q.pending = append(q.pending, m)
	q.bytes += size
	q.cond.Broadcast()
	return nil
}

func writeSync(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Get blocks until a batch is available or the queue is closed.
func (q *Queue) Get() (Batch, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.pending) == 0 && !q.closed {
		q.cond.Wait()
	}
	if q.closed {
		// after Close, nothing new is handed out; disk batches stay for next start
		return Batch{}, ErrClosed
	}
	m := q.pending[0]
	q.pending = q.pending[1:]
	q.inflight[m.id] = m
	var data []byte
	if q.dir != "" {
		d, err := os.ReadFile(q.path(m))
		if err != nil {
			delete(q.inflight, m.id)
			q.bytes -= m.size
			return Batch{}, fmt.Errorf("read spooled batch %d: %w", m.id, err)
		}
		data = d
	} else {
		data = q.mem[m.id]
	}
	return Batch{ID: m.id, Data: data, Events: m.events, Compressed: m.compressed}, nil
}

// Ack removes a delivered batch.
func (q *Queue) Ack(id uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	m, ok := q.inflight[id]
	if !ok {
		return
	}
	delete(q.inflight, id)
	if q.dir != "" {
		_ = os.Remove(q.path(m))
	} else {
		delete(q.mem, id)
	}
	q.bytes -= m.size
	q.cond.Broadcast()
}

// Nack returns an in-flight batch to the head of the queue.
func (q *Queue) Nack(id uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	m, ok := q.inflight[id]
	if !ok {
		return
	}
	delete(q.inflight, id)
	q.pending = append([]meta{m}, q.pending...)
	q.cond.Broadcast()
}

// DeadLetter moves an undeliverable batch aside (disk) or discards it (memory).
func (q *Queue) DeadLetter(id uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	m, ok := q.inflight[id]
	if !ok {
		return
	}
	delete(q.inflight, id)
	if q.dir != "" {
		_ = os.Rename(q.path(m), filepath.Join(q.dir, "dead", filepath.Base(q.path(m))))
	} else {
		delete(q.mem, id)
	}
	q.bytes -= m.size
	q.cond.Broadcast()
}

// Close wakes all waiters; Get returns ErrClosed once drained of pending work.
func (q *Queue) Close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
}
