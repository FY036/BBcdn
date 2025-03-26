package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"io"
	"sync"

	"github.com/spf13/cobra"
)

var (
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	reset  = "\033[0m"
)
func processDomain(w io.Writer, resolver *DNSResolver, ctx context.Context, domain string) {
	IsCDN, zsip, err := resolver.DetectDomainCDN(ctx, domain)
	if err != nil {
		fmt.Fprintf(w, red+"[-] "+reset+"检测失败: %v\n", err)
		return
	}
	if IsCDN {
		if zsip == "xx" {
			fmt.Fprintf(w, red+"[-] "+reset+"%s -- 无法解析域名 ("+red+"xx.xx.xx.xx"+reset+")\n", domain)
		} else {
			fmt.Fprintf(w, red+"[-] "+reset+"%s -- 存在CDN ("+red+"xx.xx.xx.xx"+reset+")\n", domain)
		}
	} else {
		fmt.Fprintf(w, green+"[+] "+reset+"%s -- 无CDN ("+yellow+"%s"+reset+")\n", domain, zsip)
	}
}
func main() {
	asciione := `
██████  ██████   ██████ ██████  ███    ██ 
██   ██ ██   ██ ██      ██   ██ ████   ██ 
██████  ██████  ██      ██   ██ ██ ██  ██ 
██   ██ ██   ██ ██      ██   ██ ██  ██ ██ 
██████  ██████   ██████ ██████  ██   ████ 
                                          
`
	fmt.Println(green + asciione + reset + "[" + red + "SaiRson" + reset + "]" + " && " + "[" + red + "fy036" + reset +"]" + " -- cdn检测工具")
resolver := NewDNSResolver()
	ctx := context.Background()
	var filename string
	var domain string
	var outputFile string
	var rootCmd = &cobra.Command{
		Use: "BBcdn",
		Run: func(cmd *cobra.Command, args []string) {
			if filename == "" && domain == "" {
				fmt.Println(yellow + "[!] " + reset + "请使用 -h 查看使用方法")
				return
			}

			if filename != "" && domain != "" {
				fmt.Println(red + "[-]" + reset + " 错误: -d 和 -f 无法同时使用")
				os.Exit(0)
			}

			// 设置输出目标
			var writers []io.Writer
			writers = append(writers, os.Stdout) // 默认输出到屏幕
			if outputFile != "" {
				file, err := os.Create(outputFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "无法创建输出文件: %v\n", err)
					os.Exit(1)
				}
				defer file.Close()
				writers = append(writers, file) // 添加文件输出
			}
			multiWriter := io.MultiWriter(writers...)

			// 处理单个域名 (-d 参数)
			if domain != "" {
				processDomain(multiWriter, resolver, ctx, domain)
			}

			// 处理文件中的域名列表 (-f 参数，使用多线程)
			if filename != "" {
				file, err := os.Open(filename)
				if err != nil {
					fmt.Fprintf(multiWriter, red+"[-] "+reset+"错误打开文件失败: %v\n", err)
					return
				}
				defer file.Close()
				scanner := bufio.NewScanner(file)
				var wg sync.WaitGroup
				for scanner.Scan() {
					domain := strings.TrimSpace(scanner.Text()) // 去掉首尾空格
					if domain == "" {
						continue // 跳过空行
					}
					wg.Add(1)
					go func(domain string) {
						defer wg.Done()
						processDomain(multiWriter, resolver, ctx, domain)
					}(domain)
				}
				wg.Wait()
				if err := scanner.Err(); err != nil {
					fmt.Fprintf(multiWriter, red+"[-] "+reset+"错误读取文件失败: %v\n", err)
				}
			}
		},
	}

	fmt.Println("")
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "指定要检测的域名")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "指定输出文件")
	rootCmd.Flags().StringVarP(&filename, "filename", "f", "", "指定域名文件{按行读取}")
	rootCmd.Execute()
	fmt.Println("")
}