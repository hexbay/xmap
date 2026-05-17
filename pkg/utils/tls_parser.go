package utils

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hexbay/xmap/pkg/types"
)

// TLS 记录类型
const (
	TLSRecordTypeHandshake       = 22
	TLSRecordTypeApplicationData = 23
)

// TLS 握手消息类型
const (
	TLSHandshakeTypeServerHello = 2
	TLSHandshakeTypeCertificate = 11
)

// TLSRecordHeaderLength TLS 记录头部长度
const TLSRecordHeaderLength = 5

// 使用 types 包中的 TLSInfo 结构体

// ExtractCertificatesFromTLSResponse 从 TLS 响应数据中提取证书和 TLS 信息
func ExtractCertificatesFromTLSResponse(data []byte) (*types.TLSInfo, error) {
	if len(data) < TLSRecordHeaderLength {
		return nil, errors.New("TLS 响应数据太短")
	}
	var certificates []*x509.Certificate
	var tlsVersion string
	var cipherSuite string
	offset := 0

	// 处理可能的多个 TLS 记录
	for offset < len(data) {
		if offset+TLSRecordHeaderLength > len(data) {
			break
		}

		// 解析 TLS 记录头部
		recordType := data[offset]
		// TLS 版本号
		recordVersion := binary.BigEndian.Uint16(data[offset+1 : offset+3])
		tlsVersion = tls.VersionName(recordVersion)
		length := binary.BigEndian.Uint16(data[offset+3 : offset+5])

		// 检查数据长度
		if offset+TLSRecordHeaderLength+int(length) > len(data) {
			break
		}

		// 检查记录类型
		if recordType == TLSRecordTypeHandshake {
			// 获取握手消息内容
			handshakeData := data[offset+TLSRecordHeaderLength : offset+TLSRecordHeaderLength+int(length)]
			handshakeOffset := 0

			// 处理可能的多个握手消息
			for handshakeOffset < len(handshakeData) {
				if handshakeOffset+4 > len(handshakeData) {
					break
				}

				// 解析握手消息头部
				handshakeType := handshakeData[handshakeOffset]
				messageLength := (uint32(handshakeData[handshakeOffset+1]) << 16) |
					(uint32(handshakeData[handshakeOffset+2]) << 8) |
					uint32(handshakeData[handshakeOffset+3])

				// 检查是否为 ServerHello 消息，提取 TLS 版本和加密套件
				if handshakeType == TLSHandshakeTypeServerHello {
					if handshakeOffset+4+int(messageLength) <= len(handshakeData) && messageLength >= 38 {
						// ServerHello 消息格式：
						// 2字节：TLS版本
						// 32字节：随机数
						// 1字节：会话ID长度
						// 变长：会话ID
						// 2字节：加密套件
						// 提取 TLS 版本
						serverVersion := binary.BigEndian.Uint16(handshakeData[handshakeOffset+4 : handshakeOffset+6])
						tlsVersion = tls.VersionName(serverVersion)
						// 提取加密套件（需要跳过随机数和会话ID）
						sessionIDLength := int(handshakeData[handshakeOffset+38])
						if handshakeOffset+39+sessionIDLength+2 <= handshakeOffset+4+int(messageLength) {
							cipherSuiteValue := binary.BigEndian.Uint16(handshakeData[handshakeOffset+39+sessionIDLength : handshakeOffset+39+sessionIDLength+2])
							cipherSuite = tls.CipherSuiteName(cipherSuiteValue)

						}
					}
				}

				// 检查是否为证书消息
				if handshakeType == TLSHandshakeTypeCertificate {
					if handshakeOffset+4+int(messageLength) > len(handshakeData) {
						break
					}

					// 提取证书数据
					certData := handshakeData[handshakeOffset+4 : handshakeOffset+4+int(messageLength)]
					certs, err := parseCertificateMessage(certData)
					if err != nil {
						return nil, fmt.Errorf("解析证书消息失败: %v", err)
					}
					certificates = append(certificates, certs...)
				}

				handshakeOffset += 4 + int(messageLength)
			}
		} else if recordType == TLSRecordTypeApplicationData {
			// 尝试直接从应用数据中解析证书
			// 某些服务器可能直接在应用数据中发送证书
			certData := data[offset+TLSRecordHeaderLength : offset+TLSRecordHeaderLength+int(length)]
			cert, err := x509.ParseCertificate(certData)
			if err == nil {
				certificates = append(certificates, cert)
			}
		}

		offset += int(length) + TLSRecordHeaderLength
	}

	// 如果没有找到证书，尝试直接解析整个数据作为证书
	if len(certificates) == 0 {
		// 尝试直接解析整个响应作为证书
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			certificates = append(certificates, cert)
		} else {
			// 尝试查找证书的开始标记 (0x30, 0x82)
			for i := 0; i < len(data)-4; i++ {
				if data[i] == 0x30 && data[i+1] == 0x82 {
					// 可能是证书的开始
					certLen := (int(data[i+2]) << 8) | int(data[i+3])
					if i+4+certLen <= len(data) {
						certData := data[i : i+4+certLen]
						cert, err := x509.ParseCertificate(certData)
						if err == nil {
							certificates = append(certificates, cert)
							break
						}
					}
				}
			}
		}
	}

	tlsInfo := &types.TLSInfo{
		Certificates: certificates,
		Version:      tlsVersion,
		TLSVersion:   tlsVersion,
		CipherSuite:  cipherSuite,
		RawData:      data,
	}

	if len(certificates) == 0 {
		return nil, errors.New("未找到证书数据")
	}

	return tlsInfo, nil
}

// parseCertificateMessage 解析 TLS Certificate 消息
func parseCertificateMessage(data []byte) ([]*x509.Certificate, error) {
	if len(data) < 3 {
		return nil, errors.New("证书消息数据太短")
	}

	// 证书链总长度
	certsLen := (uint32(data[0]) << 16) | (uint32(data[1]) << 8) | uint32(data[2])
	if int(certsLen)+3 > len(data) {
		return nil, errors.New("证书链数据长度不足")
	}

	// 证书链数据
	certsData := data[3 : 3+int(certsLen)]
	offset := 0
	var certificates []*x509.Certificate

	// 解析每个证书
	for offset < len(certsData) {
		if offset+3 > len(certsData) {
			break
		}

		// 单个证书长度
		certLen := (uint32(certsData[offset]) << 16) | (uint32(certsData[offset+1]) << 8) | uint32(certsData[offset+2])
		if offset+3+int(certLen) > len(certsData) {
			break
		}

		// 提取单个证书数据
		certData := certsData[offset+3 : offset+3+int(certLen)]
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("解析 X.509 证书失败: %v", err)
		}

		certificates = append(certificates, cert)
		offset += 3 + int(certLen)
	}

	return certificates, nil
}

// FormatName 将 pkix.Name 格式化为 map
func FormatName(name pkix.Name) map[string]interface{} {
	result := make(map[string]interface{})

	if len(name.Country) > 0 {
		result["country"] = name.Country[0]
	}
	if len(name.Organization) > 0 {
		result["organization"] = name.Organization[0]
	}
	if len(name.OrganizationalUnit) > 0 {
		result["organizational_unit"] = name.OrganizationalUnit[0]
	}
	if len(name.Locality) > 0 {
		result["locality"] = name.Locality[0]
	}
	if len(name.Province) > 0 {
		result["province"] = name.Province[0]
	}
	if name.CommonName != "" {
		result["common_name"] = name.CommonName
	}

	return result
}

// GetCertFingerprint 计算证书的 SHA-256 指纹
func GetCertFingerprint(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)
	hexStr := hex.EncodeToString(fingerprint[:])
	// 格式化为 XX:XX:XX 形式
	var formatted []string
	for i := 0; i < len(hexStr); i += 2 {
		formatted = append(formatted, hexStr[i:i+2])
	}
	return strings.Join(formatted, ":")
}

// GetPublicKeyInfo 获取证书公钥类型和位数
func GetPublicKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	case *dsa.PublicKey:
		return "DSA", pub.Parameters.P.BitLen()
	default:
		return "Unknown", 0
	}
}

// 使用 types 包中的 SSLResponse 结构体

// FormatSSLResponse 返回格式化的 SSL 响应信息
func FormatSSLResponse(resp *types.SSLResponse) string {
	if resp == nil {
		return "SSL Response: <nil>"
	}

	var sb strings.Builder
	sb.WriteString("SSL/TLS Response:\n")
	sb.WriteString(fmt.Sprintf("  TLS Version: %s\n", resp.TLSVersion))
	sb.WriteString(fmt.Sprintf("  Cipher Suite: %s\n", resp.CipherSuite))

	if resp.CertInfo != nil {
		sb.WriteString("  Certificate Information:\n")

		// 格式化主题信息
		if subject, ok := resp.CertInfo["subject"].(map[string]interface{}); ok {
			sb.WriteString("    Subject:\n")
			for k, v := range subject {
				sb.WriteString(fmt.Sprintf("      %s: %s\n", k, v))
			}
		}

		// 格式化颁发者信息
		if issuer, ok := resp.CertInfo["issuer"].(map[string]interface{}); ok {
			sb.WriteString("    Issuer:\n")
			for k, v := range issuer {
				sb.WriteString(fmt.Sprintf("      %s: %s\n", k, v))
			}
		}

		// 格式化有效期
		if notBefore, ok := resp.CertInfo["not_before"].(string); ok {
			sb.WriteString(fmt.Sprintf("    Not Before: %s\n", notBefore))
		}
		if notAfter, ok := resp.CertInfo["not_after"].(string); ok {
			sb.WriteString(fmt.Sprintf("    Not After: %s\n", notAfter))
		}

		// 格式化序列号
		if serialNumber, ok := resp.CertInfo["serial_number"].(string); ok {
			sb.WriteString(fmt.Sprintf("    Serial Number: %s\n", serialNumber))
		}

		// 格式化指纹
		if fingerprint, ok := resp.CertInfo["fingerprint"].(string); ok {
			sb.WriteString(fmt.Sprintf("    Fingerprint (SHA-1): %s\n", fingerprint))
		}

		// 格式化备用名称
		if sans, ok := resp.CertInfo["dns_names"].([]string); ok && len(sans) > 0 {
			sb.WriteString("    Subject Alternative Names:\n")
			for _, san := range sans {
				sb.WriteString(fmt.Sprintf("      - %s\n", san))
			}
		}

		// 格式化证书链
		if chain, ok := resp.CertInfo["chain"].([]map[string]interface{}); ok && len(chain) > 0 {
			sb.WriteString(fmt.Sprintf("    Certificate Chain (%d certificates):\n", len(chain)))
			for i, cert := range chain {
				sb.WriteString(fmt.Sprintf("      Certificate %d:\n", i+1))
				if subject, ok := cert["subject"].(map[string]interface{}); ok {
					sb.WriteString("        Subject:\n")
					for k, v := range subject {
						sb.WriteString(fmt.Sprintf("          %s: %s\n", k, v))
					}
				}
				if issuer, ok := cert["issuer"].(map[string]interface{}); ok {
					sb.WriteString("        Issuer:\n")
					for k, v := range issuer {
						sb.WriteString(fmt.Sprintf("          %s: %s\n", k, v))
					}
				}
				if fingerprint, ok := cert["fingerprint"].(string); ok {
					sb.WriteString(fmt.Sprintf("        Fingerprint (SHA-1): %s\n", fingerprint))
				}
			}
		}
	}

	return sb.String()
}

// ParseCertificatesFromServerHello 从 SSL 探针响应中解析证书和 TLS 信息
func ParseCertificatesFromServerHello(response []byte) (*types.SSLResponse, error) {
	// 尝试从响应中提取证书和 TLS 信息
	tlsInfo, err := ExtractCertificatesFromTLSResponse(response)
	if err != nil {
		return nil, err
	}
	// 创建 SSL 响应对象
	sslResponse := &types.SSLResponse{
		TLSVersion:  tlsInfo.TLSVersion,
		CipherSuite: tlsInfo.CipherSuite,
		JA3S:        tlsInfo.JA3S,
	}
	if len(tlsInfo.Certificates) == 0 {
		return nil, errors.New("没有发现证书")
	}
	// 提取主证书信息
	cert := tlsInfo.Certificates[0]
	certInfo := make(map[string]interface{})

	// 格式化证书主题
	subject := FormatName(cert.Subject)
	certInfo["subject"] = subject

	// 格式化证书颁发者
	issuer := FormatName(cert.Issuer)
	certInfo["issuer"] = issuer

	// 证书序列号
	certInfo["serial_number"] = cert.SerialNumber.String()

	// 证书有效期
	certInfo["not_before"] = cert.NotBefore.Format(time.RFC3339)
	certInfo["not_after"] = cert.NotAfter.Format(time.RFC3339)

	// 签名算法
	certInfo["signature_algorithm"] = cert.SignatureAlgorithm.String()

	// 替代名称 (SANs)
	if len(cert.DNSNames) > 0 {
		certInfo["dns_names"] = cert.DNSNames
	}

	// 计算证书指纹
	fingerprint := GetCertFingerprint(cert)

	// 获取公钥信息
	pubKeyType, pubKeyBits := GetPublicKeyInfo(cert)
	certInfo["fingerprint"] = fingerprint
	certInfo["public_key_type"] = pubKeyType
	certInfo["public_key_bits"] = pubKeyBits

	// 设置证书信息
	sslResponse.CertInfo = certInfo

	// Readable 字段已被移除，所有信息都在 CertInfo 中

	// 证书链信息
	if len(tlsInfo.Certificates) > 1 {
		chainInfo := make([]map[string]interface{}, 0, len(tlsInfo.Certificates)-1)
		for i := 1; i < len(tlsInfo.Certificates); i++ {
			chainCert := tlsInfo.Certificates[i]
			chainItem := make(map[string]interface{})
			chainItem["subject"] = FormatName(chainCert.Subject)
			chainItem["issuer"] = FormatName(chainCert.Issuer)
			chainItem["fingerprint"] = GetCertFingerprint(chainCert)
			chainInfo = append(chainInfo, chainItem)
		}
		certInfo["chain"] = chainInfo
	}

	// 更新 SSL 响应信息
	sslResponse.RawData = FormatSSLResponse(sslResponse)

	return sslResponse, nil
}
