package kcp

import (
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestReceivingWorkerConcurrentReadRelease(t *testing.T) {
	for range 256 {
		worker := &ReceivingWorker{window: NewReceivingWindow(), leftOver: buf.MultiBuffer{buf.FromBytes([]byte("pending bytes"))}}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; worker.Read(make([]byte, 3)) }()
		go func() { defer wg.Done(); <-start; worker.Release() }()
		close(start)
		wg.Wait()
		worker.Release()
	}
}
