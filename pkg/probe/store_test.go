package probe

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// 可视化探针排序，返回格式化的字符串表示
func visualizeProbes(probes []*Probe) string {
	if len(probes) == 0 {
		return "[空探针列表]"
	}

	var sb strings.Builder
	sb.WriteString("探针排序情况:\n")
	sb.WriteString("序号\t名称\t稀有度\t端口\t\tSSL端口\n")
	sb.WriteString("----------------------------------------\n")

	for i, p := range probes {
		ports := fmt.Sprintf("%v", p.Ports)
		sslPorts := fmt.Sprintf("%v", p.SSLPorts)
		sb.WriteString(fmt.Sprintf("%d\t%s\t%d\t%s\t%s\n",
			i+1, p.Name, p.Rarity, ports, sslPorts))
	}

	return sb.String()
}

// 检查指定探针是否在前N个位置中
func checkSorting(probes []*Probe, name string, max int) bool {
	for i := 0; i < len(probes) && i < max; i++ {
		if probes[i].Name == name {
			return true
		}
	}
	return false
}

func TestGetProbeForPort(t *testing.T) {
	store, err := GetStoreWithOptions("", 9, false)
	assert.Nil(t, err)
	testCases := []struct {
		protocol string
		port     int
		ssl      bool
		probe    string
		max      int
	}{
		{
			protocol: "tcp",
			port:     80,
			ssl:      false,
			probe:    "GetRequest",
			max:      1,
		},
		{
			protocol: "tcp",
			port:     22,
			ssl:      false,
			probe:    "NULL",
			max:      1,
		},
	}
	for _, tc := range testCases {
		probes := store.GetProbeForPort(tc.protocol, tc.port, tc.ssl)
		if checkSorting(probes, tc.probe, tc.max) {
			println("Sorted correctly")
		} else {
			println(visualizeProbes(probes))
			t.Fatal("Sorted incorrectly:", probes)

		}
	}
}

func TestSMB2NegotiateIsPreferredForPort445(t *testing.T) {
	store, err := GetStoreWithOptions("", 9, true)
	assert.NoError(t, err)
	probes := store.GetProbeForPort(TCP, 445, false)
	if assert.NotEmpty(t, probes) {
		assert.Equal(t, "SMB2NmapNegotiate", probes[0].Name)
	}
}

func TestHighRarityPortProbeSurvivesDefaultIntensity(t *testing.T) {
	store := NewProbeStore(WithVersionIntensity(7))
	err := store.LoadFromContent(`
Probe TCP RedisInfo q|INFO\r\n|
rarity 8
ports 6379
match redis m|^redis_version|

Probe TCP GenericHigh q||
rarity 8
match generic m|^generic|
`)
	assert.NoError(t, err)

	selected := store.GetProbeForPort(TCP, 6379, false)
	assert.NotEmpty(t, selected)
	for _, item := range selected {
		assert.Equal(t, "RedisInfo", item.Name)
	}

	exhaustive := store.GetAllProbesForPort(TCP, 6379, false)
	assert.True(t, checkSorting(exhaustive, "GenericHigh", len(exhaustive)))
}

func TestGetStoreWithOptionsDeduplicatesConcurrentLoads(t *testing.T) {
	originalLoader := loadStoreForOptions
	defer func() {
		loadStoreForOptions = originalLoader
	}()

	storeCacheMutex.Lock()
	storeCache = make(map[string]*Store)
	storeCacheMutex.Unlock()

	var loadCalls atomic.Int32
	started := make(chan struct{}, 32)
	release := make(chan struct{})

	loadStoreForOptions = func(fileName string, versionIntensity int) (*Store, error) {
		loadCalls.Add(1)
		started <- struct{}{}
		<-release
		return NewProbeStore(WithFileName(fileName), WithVersionIntensity(versionIntensity)), nil
	}

	const goroutines = 32
	results := make(chan *Store, goroutines)
	errs := make(chan error, goroutines)
	start := make(chan struct{})
	var ready sync.WaitGroup
	var wg sync.WaitGroup

	for range goroutines {
		ready.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			store, err := GetStoreWithOptions("test-probes", 9, false)
			errs <- err
			results <- store
		}()
	}

	ready.Wait()
	close(start)
	<-started
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	close(results)

	for err := range errs {
		assert.NoError(t, err)
	}

	var first *Store
	for store := range results {
		if first == nil {
			first = store
			continue
		}
		assert.Same(t, first, store)
	}

	assert.EqualValues(t, 1, loadCalls.Load())
}

func TestGetStoreWithOptionsSharesConcurrentLoadErrors(t *testing.T) {
	originalLoader := loadStoreForOptions
	defer func() {
		loadStoreForOptions = originalLoader
	}()

	storeCacheMutex.Lock()
	storeCache = make(map[string]*Store)
	storeCacheMutex.Unlock()

	expectedErr := errors.New("load failed")
	var loadCalls atomic.Int32
	started := make(chan struct{}, 16)
	release := make(chan struct{})

	loadStoreForOptions = func(fileName string, versionIntensity int) (*Store, error) {
		loadCalls.Add(1)
		started <- struct{}{}
		<-release
		return nil, expectedErr
	}

	const goroutines = 16
	errs := make(chan error, goroutines)
	start := make(chan struct{})
	var ready sync.WaitGroup
	var wg sync.WaitGroup

	for range goroutines {
		ready.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			_, err := GetStoreWithOptions("test-probes", 9, false)
			errs <- err
		}()
	}

	ready.Wait()
	close(start)
	<-started
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)

	for err := range errs {
		assert.ErrorIs(t, err, expectedErr)
	}

	assert.EqualValues(t, 1, loadCalls.Load())
}
