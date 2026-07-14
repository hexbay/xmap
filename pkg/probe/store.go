package probe

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// 默认探针存储实例
var (
	DefaultStore     *Store
	defaultStoreOnce sync.Once
	// 存储缓存，键为 "文件路径_版本强度"
	storeCache      = make(map[string]*Store)
	storeCacheMutex sync.RWMutex
)

//go:embed nmap-service-probes
var defaultProbes string

var DefaultVersionIntensity = 7

type Store struct {
	// 互斥锁保护并发访问
	mutex sync.RWMutex
	// 按名称索引的探针映射
	ProbesByName map[string]*Probe
	// TCP探针列表
	TCPProbes []*Probe
	// UDP探针列表
	UDPProbes []*Probe
	// 版本强度，用于过滤探针
	versionIntensity int
	// 探针文件名，不包含路径
	fileName string
}

type StoreOption func(*Store)

func WithFileName(fileName string) StoreOption {
	return func(store *Store) {
		store.fileName = fileName
	}
}

func WithVersionIntensity(versionIntensity int) StoreOption {
	return func(store *Store) {
		store.versionIntensity = versionIntensity
	}
}

// NewProbeStore 创建新的探针存储
func NewProbeStore(opts ...StoreOption) *Store {
	store := &Store{
		ProbesByName:     make(map[string]*Probe),
		TCPProbes:        make([]*Probe, 0),
		UDPProbes:        make([]*Probe, 0),
		fileName:         "",
		versionIntensity: DefaultVersionIntensity,
	}
	for _, opt := range opts {
		opt(store)
	}
	return store
}
func (ps *Store) Load() error {
	var err error
	if ps.fileName == "" {
		err = ps.LoadFromContent(defaultProbes)
	} else {
		err = ps.LoadFromFile(ps.fileName)
	}
	if err != nil {
		return err
	}
	err = ps.SetFallbackProbes()
	return err
}

// LoadFromContent 从字符串内容加载探针
func (ps *Store) LoadFromContent(content string) error {
	// 调用 parser.go 中的 ParseProbes 函数
	probes, err := ParseProbes(content)
	if err != nil {
		return err
	}
	for _, probe := range probes {
		// 根据版本强度过滤探针
		if probe.Rarity <= ps.versionIntensity {
			ps.AddProbe(probe)
		}
	}
	return nil
}

// LoadFromFile 从文件加载探针
func (ps *Store) LoadFromFile(filePath string) error {
	// 读取文件内容
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	return ps.LoadFromContent(string(content))
}

// AddProbe 添加探针到存储
func (ps *Store) AddProbe(probe *Probe) {
	if probe == nil {
		return
	}
	ps.mutex.Lock()
	defer ps.mutex.Unlock()
	// 使用协议/名称作为键
	key := probe.Protocol + "/" + probe.Name
	// 考虑有些跨协议匹配
	ps.ProbesByName[probe.Name] = probe
	ps.ProbesByName[key] = probe
	if probe.Protocol == TCP {
		ps.TCPProbes = append(ps.TCPProbes, probe)
	} else if probe.Protocol == UDP {
		ps.UDPProbes = append(ps.UDPProbes, probe)
	} else {
		gologger.Warning().Msgf("Unsupported protocol: %s", probe.Protocol)
	}
}

// SetFallbackProbes 设置探针的fallback引用
func (ps *Store) SetFallbackProbes() error {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()
	// 首先收集所有探针名称，确保所有探针都已加载
	allProbes := make(map[string]*Probe)
	for name, probe := range ps.ProbesByName {
		allProbes[name] = probe
	}

	// 然后设置fallback引用
	for _, probe := range ps.ProbesByName {
		if len(probe.Fallback) > 0 {
			// 预分配容量以提高性能
			probe.FallbackProbes = make([]*Probe, 0, len(probe.Fallback))
			for _, fallbackName := range probe.Fallback {
				// 尝试使用协议/名称格式查找 支持跨协议匹配
				fallbackKey := probe.Protocol + "/" + fallbackName
				fallbackProbe, ok := allProbes[fallbackKey]
				// 如果找不到，尝试直接使用名称查找
				if !ok {
					fallbackProbe, ok = allProbes[fallbackName]
				}
				if ok {
					probe.FallbackProbes = append(probe.FallbackProbes, fallbackProbe)
				} else {
					// 记录找不到的fallback探针
					gologger.Debug().Msgf("找不到fallback探针: %s -> %s", probe.Name, fallbackName)
				}
			}
		}
	}
	return nil
}

// GetProbesByName 根据名称获取探针
func (ps *Store) GetProbesByName(name string) *Probe {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	return ps.ProbesByName[name]
}

// GetTCPProbes 获取TCP探针列表
func (ps *Store) GetTCPProbes() []*Probe {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	return ps.TCPProbes
}

// GetUDPProbes 获取UDP探针列表
func (ps *Store) GetUDPProbes() []*Probe {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	return ps.UDPProbes
}

// GetAllProbes 获取所有探针列表
func (ps *Store) GetAllProbes() []*Probe {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	// 合并 TCP 和 UDP 探针
	allProbes := make([]*Probe, 0, len(ps.TCPProbes)+len(ps.UDPProbes))
	allProbes = append(allProbes, ps.TCPProbes...)
	allProbes = append(allProbes, ps.UDPProbes...)
	return allProbes
}

// GetProbe 根据协议和名称获取探针
func (ps *Store) GetProbe(protocol, name string) *Probe {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()
	key := protocol + "/" + name
	return ps.ProbesByName[key]
}

// GetDefaultProbeFilePath 获取默认的探针文件路径
func GetDefaultProbeFilePath() string {
	// 首先尝试从环境变量获取
	if path := os.Getenv("NMAP_PROBE_FILE"); path != "" {
		return path
	}
	// home 目录
	homeDir, _ := os.UserHomeDir()
	// 然后尝试常见的位置
	commonPaths := []string{
		"nmap-service-probes",
		homeDir + "/nmap-service-probes",
	}
	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func InitDefaultStore() error {
	var err error
	defaultStoreOnce.Do(func() {
		// 初始化 DefaultStore
		probeFilePath := GetDefaultProbeFilePath()
		versionIntensity := DefaultVersionIntensity

		// 生成缓存键
		cacheKey := GetCacheKey(probeFilePath, versionIntensity)

		// 先尝试从缓存获取
		storeCacheMutex.RLock()
		if store, ok := storeCache[cacheKey]; ok {
			DefaultStore = store
			storeCacheMutex.RUnlock()
			return
		}
		storeCacheMutex.RUnlock()

		// 缓存中不存在，创建新的存储
		storeCacheMutex.Lock()
		defer storeCacheMutex.Unlock()

		// 双重检查，避免并发创建
		if store, ok := storeCache[cacheKey]; ok {
			DefaultStore = store
			return
		}

		// 创建新的存储
		DefaultStore = NewProbeStore(WithVersionIntensity(versionIntensity), WithFileName(probeFilePath))
		err = DefaultStore.Load()
		if err != nil {
			gologger.Warning().Msgf("从文件加载探针失败: %v，将使用内置探针", err)
			err = DefaultStore.LoadFromContent(defaultProbes)
		} else {
			gologger.Debug().Msgf("从文件加载探针成功: %s", probeFilePath)
			storeCache[cacheKey] = DefaultStore
		}
	})
	return err
}

func GetDefaultStore() *Store {
	if DefaultStore == nil {
		_ = InitDefaultStore()
	}
	return DefaultStore
}

// GetCacheKey 根据文件名和版本强度生成缓存键
func GetCacheKey(fileName string, versionIntensity int) string {
	// 提取文件名，不包含路径
	baseName := fileName
	if fileName != "" {
		// 如果是完整路径，提取文件名
		baseName = filepath.Base(fileName)
	} else {
		// 如果是空字符串，使用“default”
		baseName = "default"
	}

	// 生成缓存键
	return fmt.Sprintf("%s_%d", baseName, versionIntensity)
}

// GetStoreWithOptions GetStoreWithIntensity 获取指定版本强度的探针存储
func GetStoreWithOptions(filename string, versionIntensity int, reload bool) (*Store, error) {
	cacheKey := GetCacheKey(filename, versionIntensity)
	storeCacheMutex.RLock()
	if !reload {
		if store, ok := storeCache[cacheKey]; ok {
			storeCacheMutex.RUnlock()
			return store, nil
		}
	}
	storeCacheMutex.RUnlock()
	probeFilePath := filename
	if probeFilePath == "" {
		probeFilePath = GetDefaultProbeFilePath()
	}
	store := NewProbeStore(WithFileName(probeFilePath), WithVersionIntensity(versionIntensity))
	if err := store.Load(); err != nil {
		return nil, err
	}
	storeCacheMutex.Lock()
	storeCache[cacheKey] = store
	storeCacheMutex.Unlock()
	return store, nil
}

// Clear 清空探针存储
func (ps *Store) Clear() {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()
	ps.ProbesByName = make(map[string]*Probe)
	ps.TCPProbes = make([]*Probe, 0)
	ps.UDPProbes = make([]*Probe, 0)
}

// GetProbeForPort 获取适用于指定端口的探针列表，先按端口精确匹配度排序，再按稀有度排序
func (ps *Store) GetProbeForPort(protocol string, port int, ssl bool) []*Probe {
	ps.mutex.RLock()
	defer ps.mutex.RUnlock()

	var probes []*Probe
	if protocol == TCP {
		probes = ps.TCPProbes
	} else if protocol == UDP {
		probes = ps.UDPProbes
	} else {
		return nil
	}
	// 使用二维数组分类探针：[0]精确匹配端口的探针，[1]范围匹配 端口的探针，[2]其他
	classifiedProbes := make([][]*Probe, 3)
	classifiedProbes[0] = make([]*Probe, 0) // 精准匹配
	classifiedProbes[1] = make([]*Probe, 0) // 范围匹配
	classifiedProbes[2] = make([]*Probe, 0) // 其他
	// 移除调试语句
	for _, probe := range probes {
		if ssl {
			if probe.HasExactSSLPort(port) {
				// 精确匹配 SSL 端口
				classifiedProbes[0] = append(classifiedProbes[0], probe)
			} else if probe.HasSSLPort(port) {
				// 通过端口范围匹配
				classifiedProbes[1] = append(classifiedProbes[1], probe)
			} else {
				classifiedProbes[2] = append(classifiedProbes[2], probe)
			}
		} else {
			if probe.HasExactPort(port) {
				// 精确匹配普通端口
				classifiedProbes[0] = append(classifiedProbes[0], probe)
			} else if probe.HasPort(port) {
				// 通过端口范围匹配
				classifiedProbes[1] = append(classifiedProbes[1], probe)
			} else {
				classifiedProbes[2] = append(classifiedProbes[2], probe)
			}
		}
	}
	// 分别按稀有度排序
	for i := 0; i < len(classifiedProbes); i++ {
		sort.Slice(classifiedProbes[i], func(j, k int) bool {
			return classifiedProbes[i][j].Rarity < classifiedProbes[i][k].Rarity
		})
	}
	// 返回所有探针，按照优先级排序：精确匹配 > 范围匹配 > 其他
	totalLen := len(classifiedProbes[0]) + len(classifiedProbes[1]) + len(classifiedProbes[2])
	result := make([]*Probe, 0, totalLen)

	// 先添加精确匹配的探针
	result = append(result, classifiedProbes[0]...)

	// 再添加范围匹配的探针
	result = append(result, classifiedProbes[1]...)

	// 最后添加其他探针
	result = append(result, classifiedProbes[2]...)
	return result
}
