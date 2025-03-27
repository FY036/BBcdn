package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"io"
	"regexp"
	"sync"

	"github.com/spf13/cobra"
)

// ANSI 颜色代码
var (
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	reset  = "\033[0m"
)

// 默认并发线程数
var concurrency = 30
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripAnsi(input string) string {
	return ansiRegex.ReplaceAllString(input, "")
}

// 处理域名检测
func processDomain(w io.Writer, fileWriter io.Writer, resolver *DNSResolver, ctx context.Context, domain string) {
	IsCDN, zsip, err := resolver.DetectDomainCDN(ctx, domain)
	var output string

	if err != nil {
		output = fmt.Sprintf(red+"[-] "+reset+"检测失败: %v\n", err)
	} else if IsCDN {
		if zsip == "xx" {
			output = fmt.Sprintf(red+"[-] "+reset+"%s -- 无法解析域名 ("+red+"xx.xx.xx.xx"+reset+")\n", domain)
		} else {
			output = fmt.Sprintf(red+"[-] "+reset+"%s -- 存在CDN ("+red+"xx.xx.xx.xx"+reset+")\n", domain)
		}
	} else {
		output = fmt.Sprintf(green+"[+] "+reset+"%s -- 无CDN ("+yellow+"%s"+reset+")\n", domain, zsip)
	}

	fmt.Fprint(w, output)
	fmt.Fprint(fileWriter, stripAnsi(output))
}

func main() {
	// 终端 ASCII 标志
	asciione := `
██████  ██████   ██████ ██████  ███    ██ 
██   ██ ██   ██ ██      ██   ██ ████   ██ 
██████  ██████  ██      ██   ██ ██ ██  ██ 
██   ██ ██   ██ ██      ██   ██ ██  ██ ██ 
██████  ██████   ██████ ██████  ██   ████ 
                                          
`
	fmt.Println(green + asciione + reset + "[" + red + "SaiRson" + reset + "]" + " && " + "[" + red + "fy036" + reset + "]" + " -- cdn检测工具")

	// 解析命令行参数
	var filename string
	var domain string
	var outputFile string
	var threadCount int

	// 解析命令
	var rootCmd = &cobra.Command{
		Use: "BBcdn",
		Run: func(cmd *cobra.Command, args []string) {
			// 设置并发数
			concurrency = threadCount

			if filename == "" && domain == "" {
				fmt.Println(yellow + "[!] " + reset + "请使用 -h 查看使用方法")
				return
			}

			if filename != "" && domain != "" {
				fmt.Println(red + "[-]" + reset + " 错误: -d 和 -f 无法同时使用")
				os.Exit(1)
			}

			// 终端输出 Writer
			terminalWriter := os.Stdout

			// 文件输出 Writer
			var fileWriter io.Writer = io.Discard
			if outputFile != "" {
				file, err := os.Create(outputFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "无法创建输出文件: %v\n", err)
					os.Exit(1)
				}
				defer file.Close()
				fileWriter = file
			}

			// 初始化 DNS 解析器
			resolver := NewDNSResolver()
			ctx := context.Background()

			// 处理单个域名
			if domain != "" {
				processDomain(terminalWriter, fileWriter, resolver, ctx, domain)
			}

			// 处理文件中的域名列表
			if filename != "" {
				file, err := os.Open(filename)
				if err != nil {
					fmt.Fprintf(terminalWriter, red+"[-] "+reset+"错误打开文件失败: %v\n", err)
					return
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				var wg sync.WaitGroup
				semaphore := make(chan struct{}, concurrency) // 控制并发

				for scanner.Scan() {
					domain := strings.TrimSpace(scanner.Text())
					if domain == "" {
						continue
					}

					wg.Add(1)
					semaphore <- struct{}{}
					go func(domain string) {
						defer wg.Done()
						defer func() { <-semaphore }() // 释放令牌
						processDomain(terminalWriter, fileWriter, resolver, ctx, domain)
					}(domain)
				}

				wg.Wait()
				if err := scanner.Err(); err != nil {
					fmt.Fprintf(terminalWriter, red+"[-] "+reset+"错误读取文件失败: %v\n", err)
				}
			}
		},
	}

	// 添加命令行参数
    fmt.Println("")
    rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "指定要检测的域名")
    rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "指定输出文件")
    rootCmd.Flags().StringVarP(&filename, "filename", "f", "", "指定域名文件{按行读取}")
    rootCmd.Flags().IntVarP(&threadCount, "thread", "t", 30, "指定并发线程数{默认 30}")
    rootCmd.Execute()
    fmt.Println("")
}
