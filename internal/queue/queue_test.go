package queue

import (
	"fmt"
	"testing"
)

func TestDiskPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	q, _ := New(dir, 1<<20, DropOldest)
	for i := 0; i < 5; i++ {
		_ = q.Put([]byte(fmt.Sprintf("batch-%d\n", i)), 1, false)
	}
	b, _ := q.Get()
	q.Ack(b.ID)
	b2, _ := q.Get() // in flight at "crash"
	_ = b2
	q2, err := New(dir, 1<<20, DropOldest)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := q2.Len(); n != 4 {
		t.Fatalf("want 4 recovered (incl. in-flight), got %d", n)
	}
	first, _ := q2.Get()
	if string(first.Data) != "batch-1\n" {
		t.Fatalf("FIFO order broken: %q", first.Data)
	}
	_ = q2.Put([]byte("new\n"), 1, false)
	if first.ID >= q2.nextID {
		t.Fatal("ids must keep increasing after recovery")
	}
}

func TestDropOldest(t *testing.T) {
	q, _ := New("", 30, DropOldest)
	dropped := 0
	q.OnDrop = func(Batch) { dropped++ }
	for i := 0; i < 5; i++ {
		_ = q.Put([]byte("0123456789"), 1, false)
	}
	if n, b := q.Len(); n != 3 || b != 30 || dropped != 2 {
		t.Fatalf("n=%d b=%d dropped=%d", n, b, dropped)
	}
	b, _ := q.Get()
	if b.ID != 3 {
		t.Fatalf("oldest should be evicted first, got id %d", b.ID)
	}
}

func TestNackRequeuesAtHead(t *testing.T) {
	q, _ := New("", 1<<20, Block)
	_ = q.Put([]byte("a"), 1, false)
	_ = q.Put([]byte("b"), 1, false)
	a, _ := q.Get()
	q.Nack(a.ID)
	again, _ := q.Get()
	if string(again.Data) != "a" {
		t.Fatal("nack should requeue at head")
	}
}
