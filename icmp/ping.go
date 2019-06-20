package main

import (
	"encoding/binary"
	"net"
	"flag"
	"fmt"
	"time"
	"bytes"
	"math"
	"log"
)

// ICMP Type 8bit + Code 8 bit + checksum 8 bit + ID 16 bit + sequence 16 bit + data
// Type 0: request 8:reply
type ICMP struct {
	Type        uint8
	Code        uint8
	Checksum    uint16
	Identifier  uint16
	SequenceNum uint16
}

var (
	icmp    ICMP
	ip      string
	num     int
	timeout int
	size    int
)

func ParseArgs() {
	flag.StringVar(&ip, "ip", "127.0.0.1", "要ping的主机地址")
	flag.IntVar(&num, "n", 10, "发送的请求数")
	flag.IntVar(&size, "s", 32, "要发送的缓冲区大小")
	flag.IntVar(&timeout, "t", 1000, "响应超时时间(单位ms)")
	flag.Parse()
}

func main() {
	var (
		conn         net.Conn
		err          error
		buffer       bytes.Buffer
		successCount int                  // 成功次数
		failCount    int                  // 失败次数
		minTime            = int(math.MaxInt32) // 最短响应时间
		maxTime      int                  // 最长响应时间
		totalTime    int
	)
	ParseArgs()
	if conn, err = net.DialTimeout("ip:icmp", ip, time.Duration(timeout)*time.Millisecond); err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	// 初始化icmp
	icmp.Type = 8
	icmp.Code = 0
	icmp.Checksum = 0
	icmp.Identifier = 1
	icmp.SequenceNum = 1
	fmt.Printf("\n 开始ping %s 具有 %d 字节的数据:\n", ip, size)

	binary.Write(&buffer, binary.LittleEndian, icmp) // 小端模式
	data := make([]byte, size)
	buffer.Write(data)
	data = buffer.Bytes()

	for i := 0; i < num; i++ {
		icmp.SequenceNum = uint16(1)
		// 检验和设为0
		data[2] = byte(0)
		data[3] = byte(0)

		data[6] = byte(icmp.SequenceNum >> 8)
		data[7] = byte(icmp.SequenceNum)
		icmp.Checksum = checkSum(data)
		data[2] = byte(icmp.Checksum >> 8)
		data[3] = byte(icmp.Checksum)

		// 开始时间
		t1 := time.Now()
		conn.SetDeadline(t1.Add(time.Duration(time.Duration(timeout) * time.Millisecond)))
		n, err := conn.Write(data)
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, 65535)
		if	n, err = conn.Read(buf);err != nil {
			fmt.Println("请求超时。")
			failCount++
			continue
		}
		et := int(time.Since(t1) / 1000000)	// 转换成ms
		if minTime > et {
			minTime = et
		}
		if maxTime < et {
			maxTime = et
		}
		totalTime += et
		fmt.Printf("来自 %s 的回复: 字节=%d 时间=%dms TTL=%d\n", ip, len(buf[28:n]), et, buf[8])
		successCount++
		time.Sleep(1 * time.Second)
	}
	fmt.Printf("\n%s 的 Ping 统计信息:\n", ip)
	fmt.Printf("    数据包: 已发送 = %d，已接收 = %d，丢失 = %d (%.2f%% 丢失)，\n", successCount+failCount, successCount, failCount, float64(failCount*100)/float64(successCount+failCount))
	if maxTime != 0 && minTime != int(math.MaxInt32) {
		fmt.Printf("往返行程的估计时间(以毫秒为单位):\n")
		fmt.Printf("    最短 = %dms，最长 = %dms，平均 = %dms\n", minTime, maxTime, totalTime/successCount)
	}

}

// checkSum 计算ICMP的校验值
func checkSum(data []byte) uint16 {
	var (
		sum   uint32
		lens  = len(data)
		index int
	)
	for lens > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		lens -= 2
	}

	if lens == 1 {
		sum += uint32(data[index])
	}

	sum = uint32(sum>>16) + uint32(sum)
	sum = uint32(sum>>16) + uint32(sum)

	return uint16(^sum)
}
