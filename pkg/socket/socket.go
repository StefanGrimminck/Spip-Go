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
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw connection: %w", err)
	}

	var addr C.struct_sockaddr_in
	var opErr error

	controlErr := rawConn.Control(func(fd uintptr) {
		if C.get_original_dst(C.int(fd), &addr) != 0 {
			opErr = fmt.Errorf("failed to get original destination")
			return
		}
	})
	if controlErr != nil {
		return nil, fmt.Errorf("control error: %w", controlErr)
	}
	if opErr != nil {
		return nil, opErr
	}

	ip := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&ip[0])) = uint32(addr.sin_addr.s_addr)

	portBytes := (*[2]byte)(unsafe.Pointer(&addr.sin_port))
	port := binary.BigEndian.Uint16(portBytes[:])

	return &OriginalDst{
		IP:   net.IP(ip),
		Port: port,
	}, nil
}
