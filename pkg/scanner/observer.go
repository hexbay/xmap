package scanner

import (
	"errors"
	"github.com/hexbay/xmap/pkg/types"
)

// PortObserverEntry 表示一个端口状态观测记录
type PortObserverEntry struct {
	target               *types.ScanTarget
	Close                int    // 连接失败总次数
	isOpen               bool   // 连接成功总次数
	ReadOk               int    // 读取到数据的次数
	consecutiveClose     int    // 连续失败次数
	ConsecutiveOpen      int    // 连续成功次数
	LastFailureType      string // 最后一次失败类型（timeout, refused等）
	ReadTimeout          int    // 读取超时次数
	WriteTimeout         int    // 写入超时次数
	FailuresSinceSuccess int    // 上次成功后的失败次数
	reason               string
	NotMatch             int  // 未匹配上次数
	Terminate            bool // 是否可以判断端口已经关闭
}

func NewPortObserverEntry(target *types.ScanTarget) *PortObserverEntry {
	return &PortObserverEntry{
		target:               target,
		Close:                0,
		isOpen:               false,
		ReadOk:               0,
		consecutiveClose:     0,
		ConsecutiveOpen:      0,
		LastFailureType:      "",
		ReadTimeout:          0,
		WriteTimeout:         0,
		FailuresSinceSuccess: 0,
		reason:               "",
		NotMatch:             0,
		Terminate:            false,
	}
}

func (p *PortObserverEntry) Reset() {
	p.Close = 0
	p.isOpen = false
	p.ReadOk = 0
	p.consecutiveClose = 0
	p.ConsecutiveOpen = 0
	p.LastFailureType = ""
	p.ReadTimeout = 0
	p.WriteTimeout = 0
	p.FailuresSinceSuccess = 0
	p.reason = ""
	p.NotMatch = 0
	p.Terminate = false
}
func (p *PortObserverEntry) watch(response []byte, err error) {
	//	通过观察结果、更新观察状态
	if len(response) > 0 {
		p.isOpen = true
		p.consecutiveClose = 0
		p.ReadTimeout = 0
		p.WriteTimeout = 0
		return
	}
	if err != nil {
		if errors.Is(err, ConnectionError) {
			// 创建连接失败
			p.consecutiveClose++
		} else if errors.Is(err, ReadTimeoutError) {
			p.ReadTimeout++
		} else if errors.Is(err, WriteDataError) {
			p.WriteTimeout++
		}
	}

}

// IsTerminate 判断是否需要停止扫描
func (p *PortObserverEntry) IsTerminate() (bool, string) {
	if p.consecutiveClose >= 3 {
		// 建立链接失败次数过多
		return true, "connect_failed too many times than 3"
	}
	if p.ReadTimeout >= 10 {
		return true, "read_timeout too many times than 10"
	}
	if p.WriteTimeout >= 3 {
		return true, "write_timeout too many times than 3"
	}
	return false, ""
}
