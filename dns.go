package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	cdnIPSThreshold = 2 // 两个以上的不同IP则判定为CDN
)

type CheckResult struct {
	IsCDN        bool
	Reason       string
	IPs          []net.IP
	CNAMETargets []string
}

type DNSResolver struct {
	client           *dns.Client
	cache            *sync.Map
	dnsServers       []string
	cdnCNAMEPatterns []string
}

func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		client: &dns.Client{
			Timeout: 5 * time.Second,
			Net:     "udp",
		},
		cache: &sync.Map{},
		dnsServers: []string{
			"114.114.114.114:53",
			"8.8.8.8:53",
			"1.1.1.1:53",
			"9.9.9.9:53",
			"208.67.222.222:53",
			"84.200.69.80:53",
			"223.6.6.6:53",
			"223.5.5.5:53",
			"119.29.29.29:53",
			"103.86.96.100:53",
			"182.254.116.116:53",
			"156.154.70.1:53",
			"194.146.106.194:53",
			"45.90.28.0:53",
			"185.228.168.9:53",
			"76.76.2.0:53",
			"94.140.14.14:53",
			"64.6.64.6:53",
		},
		cdnCNAMEPatterns: []string{
			// 国际CDN
			".cloudfront.net.",     // AWS CloudFront
			".akamaized.net.",      // Akamai
			".akamaicdn.org.",      // Akamai
			".edgesuite.net.",      // Akamai
			".edgekey.net.",        // Akamai
			".fastly.net.",         // Fastly
			".cdn.cloudflare.net.", // Cloudflare
			".azureedge.net.",      // Microsoft Azure CDN
			".stackpathdns.com.",   // StackPath
			".incapdns.net.",       // Incapsula
			".cdngc.net.",          // CDNetworks
			".kxcdn.com.",          // KeyCDN
			".b-cdn.net.",          // BunnyCDN
			".lldns.net.",          // Limelight
			".hwcdn.net.",          // Highwinds

			// 国内CDN
			".alikunlun.com.",    // 阿里云CDN
			".kunlun.com.",       // 阿里云CDN
			".alicdn.com.",       // 阿里云CDN
			".cdnga.com.",        // 阿里云全球加速
			".lxdns.com.",        // 网宿科技
			".wscdns.com.",       // 网宿科技
			".chinacache.net.",   // 网宿科技
			".cdn.dnsv1.com.",    // 腾讯云CDN
			".tcdn.qq.com.",      // 腾讯云CDN
			".cdnhwc1.com.",      // 华为云CDN
			".cdnhwc2.com.",      // 华为云CDN
			".cdnhwc3.com.",      // 华为云CDN
			".cdnhwccs.com.",     // 华为云
			".su.baidubce.com.",  // 百度云加速
			".bdydns.com.",       // 百度云加速
			".jomodns.com.",      // 知道创宇
			".qingcdn.com.",      // 白山云
			".21cvcdn.com.",      // 世纪互联
			".cdnsvc.com.",       // 蓝汛
			".cachecn.com.",      // 同兴万点
			".ourdvsss.com.",     // 帝联科技
			".yunjiasu-cdn.net.", // 百度智能云

			// 其他常见
			".msecnd.net.",  // Microsoft Azure中国版
			".cdntip.com.",  // 腾讯云海外加速
			".cdn20.com.",   // UCloud
			".cdntips.com.", // 腾讯云海外
			".gccdn.cn.",    // 高防CDN
			".cdntip.net.",  // 腾讯云
			".txcdn.cn.",    // 腾讯云
		},
	}
}

// DetectDomainCDN 主检测入口
func (r *DNSResolver) DetectDomainCDN(ctx context.Context, domain string) (bool,string, error) {
	result := &CheckResult{}

	// 并行执行两种检测
	var wg sync.WaitGroup
	wg.Add(2)

	// 1. 全球DNS解析
	go func() {
		defer wg.Done()
		ips, names, _ := r.globalDNSResolution(ctx, domain)
		result.IPs = ips
		result.CNAMETargets = names
	}()

	// 2. CNAME检测
	go func() {
		defer wg.Done()
		if names, _ := r.resolveCNAMEChain(domain); len(names) > 0 {
			result.CNAMETargets = names
		}
	}()

	wg.Wait()
	r.analyzeResults(result)
	if len(result.IPs) == 0 {
	    return true, "xx",nil
	}
	return result.IsCDN,result.IPs[0].String(), nil
}

// 全球DNS解析（并发查询）
func (r *DNSResolver) globalDNSResolution(ctx context.Context, domain string) ([]net.IP, []string, error) {
	var ips []net.IP
	var names []string
	var mu sync.Mutex

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 并发控制

	for _, server := range r.dnsServers {
		wg.Add(1)
		sem <- struct{}{}

		go func(srv string) {
			defer wg.Done()
			defer func() { <-sem }()

			msg := dns.Msg{}
			msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			response, _, err := r.client.ExchangeContext(ctx, &msg, srv)
			if err != nil || response == nil {
				return
			}

			mu.Lock()
			defer mu.Unlock()

			for _, ans := range response.Answer {
				switch rr := ans.(type) {
				case *dns.A:
					ip := rr.A.To4()
					if ip != nil && !containsIP(ips, ip) {
						ips = append(ips, ip)
					}
				case *dns.CNAME:
					target := dns.Fqdn(rr.Target)
					if !containsStr(names, target) {
						names = append(names, target)
					}
				}
			}
		}(server)
	}

	wg.Wait()
	return deduplicateIPs(ips), names, nil
}

// 递归解析CNAME链
func (r *DNSResolver) resolveCNAMEChain(domain string) ([]string, error) {
	var names []string
	visited := make(map[string]bool)

	for depth := 0; depth < 10; depth++ {
		if visited[domain] {
			return nil, errors.New("cname loop detected")
		}
		visited[domain] = true

		msg := dns.Msg{}
		msg.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)

		response, _, err := r.client.Exchange(&msg, r.selectOptimalDNS())
		if err != nil || response == nil {
			break
		}

		found := false
		for _, ans := range response.Answer {
			if cname, ok := ans.(*dns.CNAME); ok {
				domain = dns.Fqdn(cname.Target)
				names = append(names, domain)
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return names, nil
}

// 智能选择DNS服务器
func (r *DNSResolver) selectOptimalDNS() string {
	return r.dnsServers[time.Now().Unix()%int64(len(r.dnsServers))]
}

// 结果分析逻辑（精简版）
func (r *DNSResolver) analyzeResults(result *CheckResult) {
	// 1. CNAME匹配检测
	for _, cname := range result.CNAMETargets {
		for _, pattern := range r.cdnCNAMEPatterns {
			if strings.Contains(cname, pattern) {
				result.IsCDN = true
				result.Reason = fmt.Sprintf("A match of CNAME[%s] is detected, proving the presence of a CDN", pattern)
				return
			}
		}
	}

	// 2. IP数量检测
	if len(result.IPs) >= cdnIPSThreshold {
		result.IsCDN = true
		result.Reason = fmt.Sprintf("%d different IP addresses were detected, proving the presence of a CDN", len(result.IPs))
	}
}

// 工具函数
func containsIP(ips []net.IP, ip net.IP) bool {
	for _, existing := range ips {
		if existing.Equal(ip) {
			return true
		}
	}
	return false
}

func deduplicateIPs(ips []net.IP) []net.IP {
	seen := make(map[string]bool)
	var result []net.IP
	for _, ip := range ips {
		key := ip.String()
		if !seen[key] {
			seen[key] = true
			result = append(result, ip)
		}
	}
	return result
}

func containsStr(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
