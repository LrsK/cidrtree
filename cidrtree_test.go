package cidrtree

import (
	"fmt"
	"net"
	"testing"
)

func TestMain(t *testing.T) {
	ct := NewCIDRTree()
	ip1 := net.ParseIP("223.252.161.0")
	ct.AddIPData(ip1.To4(), "USA")
	ip2 := net.ParseIP("223.252.161.64")
	ct.AddIPData(ip2.To4(), "Australia")
	ip3 := net.ParseIP("223.252.161.128")
	ct.AddIPData(ip3.To4(), "Norway")

	f, _ := ct.FindDataByIP(net.ParseIP("223.252.161.2").To4())
	fmt.Println(f)
	f, _ = ct.FindDataByIP(net.ParseIP("223.252.161.88").To4())
	fmt.Println(f)
	f, _ = ct.FindDataByIP(net.ParseIP("223.252.161.200").To4())
	fmt.Println(f)
}
