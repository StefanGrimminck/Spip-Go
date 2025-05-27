package socket

/*
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netfilter_ipv4.h>

int get_original_dst(int fd, struct sockaddr_in *addr) {
    socklen_t addr_len = sizeof(*addr);
    return getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, addr, &addr_len);
}
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

// OriginalDst represents the original destination of a redirected connection
type OriginalDst struct {
	IP   net.IP
	Port uint16
}

// GetOriginalDst retrieves the original destination of a redirected TCP connection
func GetOriginalDst(conn *net.TCPConn) (*OriginalDst, error) {
	file, err := conn.File()
	if err != nil {
		return nil, fmt.Errorf("failed to get file descriptor: %w", err)
	}
	defer file.Close()

	fd := C.int(file.Fd())
	var addr C.struct_sockaddr_in
	if C.get_original_dst(fd, &addr) != 0 {
		return nil, fmt.Errorf("failed to get original destination")
	}

	ip := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&ip[0])) = uint32(addr.sin_addr.s_addr)

	// Convert port from network byte order (big-endian) to host byte order
	// This matches the Rust implementation's u16::from_be(addr.sin_port)
	portBytes := (*[2]byte)(unsafe.Pointer(&addr.sin_port))
	port := binary.BigEndian.Uint16(portBytes[:])

	return &OriginalDst{
		IP:   net.IP(ip),
		Port: port,
	}, nil
}
