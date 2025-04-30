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
func processDomain(w io.Writer, fileWriter io.Writer, ipOnlyWriter io.Writer, resolver *DNSResolver, ctx context.Context, domain string) {
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
		if ipOnlyWriter != nil {
			fmt.Fprintln(ipOnlyWriter, zsip)
		}
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

	// 参数变量
	var filename string
	var domain string
	var outputFile string
	var outputIPFile string
	var threadCount int

	// 命令定义
	var rootCmd = &cobra.Command{
		Use: "BBcdn",
		Run: func(cmd *cobra.Command, args []string) {
			concurrency = threadCount

			if filename == "" && domain == "" {
				fmt.Println(yellow + "[!] " + reset + "请使用 -h 查看使用方法")
				return
			}
			if filename != "" && domain != "" {
				fmt.Println(red + "[-]" + reset + " 错误: -d 和 -f 无法同时使用")
				os.Exit(1)
			}

			terminalWriter := os.Stdout

			// 输出文件
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

			// IP-only 输出
			var ipOnlyWriter io.Writer = nil
			if outputIPFile != "" {
				ipFile, err := os.Create(outputIPFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "无法创建 IP 输出文件: %v\n", err)
					os.Exit(1)
				}
				defer ipFile.Close()
				ipOnlyWriter = ipFile
			}

			resolver := NewDNSResolver()
			ctx := context.Background()

			if domain != "" {
				processDomain(terminalWriter, fileWriter, ipOnlyWriter, resolver, ctx, domain)
			}

			if filename != "" {
				file, err := os.Open(filename)
				if err != nil {
					fmt.Fprintf(terminalWriter, red+"[-] "+reset+"错误打开文件失败: %v\n", err)
					return
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				var wg sync.WaitGroup
				semaphore := make(chan struct{}, concurrency)

				for scanner.Scan() {
					domain := strings.TrimSpace(scanner.Text())
					if domain == "" {
						continue
					}

					wg.Add(1)
					semaphore <- struct{}{}
					go func(domain string) {
						defer wg.Done()
						defer func() { <-semaphore }()
						processDomain(terminalWriter, fileWriter, ipOnlyWriter, resolver, ctx, domain)
					}(domain)
				}

				wg.Wait()
				if err := scanner.Err(); err != nil {
					fmt.Fprintf(terminalWriter, red+"[-] "+reset+"错误读取文件失败: %v\n", err)
				}
			}
		},
	}
	fmt.Println("")
	// 参数绑定
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "指定要检测的域名")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "指定输出文件")
	rootCmd.Flags().StringVarP(&filename, "filename", "f", "", "指定域名文件{按行读取}")
	rootCmd.Flags().IntVarP(&threadCount, "thread", "t", 30, "指定并发线程数 (默认 30)")
	rootCmd.Flags().StringVarP(&outputIPFile, "output-ip", "O", "", "只保存无CDN的IP地址")

	// 自定义帮助顺序
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), `用法:
  BBcdn [flags]

可用参数:
  -h, --help               显示帮助信息
  -d, --domain string      指定要检测的域名
  -f, --filename string    指定域名文件{按行读取}
  -o, --output string      指定输出文件
  -O, --output-ip string   只保存无CDN的IP地址
  -t, --thread int         指定并发线程数(默认 30)

`)
		return nil
	})

	rootCmd.Execute()
	fmt.Println("")
}
