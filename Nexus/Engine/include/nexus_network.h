/**
 * @file nexus_network.h
 * @brief TCP/UDP connection enumeration for target processes.
 *
 * Uses the IP Helper API (GetExtendedTcpTable / GetExtendedUdpTable)
 * to list active network connections belonging to a specific process,
 * with local/remote address and port information.
 */

#ifndef NEXUS_NETWORK_H
#define NEXUS_NETWORK_H

#include "nexus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Network Types
 * ============================================================================ */

typedef enum NexusNetProtocol {
    NEXUS_NET_TCP = 0,
    NEXUS_NET_UDP = 1,
    NEXUS_NET_TCP6 = 2,
    NEXUS_NET_UDP6 = 3
} NexusNetProtocol;

typedef enum NexusTcpState {
    NEXUS_TCP_CLOSED = 1,
    NEXUS_TCP_LISTEN = 2,
    NEXUS_TCP_SYN_SENT = 3,
    NEXUS_TCP_SYN_RCVD = 4,
    NEXUS_TCP_ESTABLISHED = 5,
    NEXUS_TCP_FIN_WAIT1 = 6,
    NEXUS_TCP_FIN_WAIT2 = 7,
    NEXUS_TCP_CLOSE_WAIT = 8,
    NEXUS_TCP_CLOSING = 9,
    NEXUS_TCP_LAST_ACK = 10,
    NEXUS_TCP_TIME_WAIT = 11,
    NEXUS_TCP_DELETE_TCB = 12
} NexusTcpState;

/* ============================================================================
 * Network Structures
 * ============================================================================ */

typedef struct NexusIpAddress {
    uint8_t bytes[16];                  /* IPv4 or IPv6 address */
    uint32_t isIpv6;                    /* 1 if IPv6 */
    uint32_t reserved;
} NexusIpAddress;

typedef struct NexusTcpConnection {
    uint32_t processId;                 /* Owner process ID */
    uint32_t state;                     /* NexusTcpState */
    NexusIpAddress localAddress;        /* Local address */
    uint16_t localPort;                 /* Local port */
    uint16_t reserved1;
    NexusIpAddress remoteAddress;       /* Remote address */
    uint16_t remotePort;                /* Remote port */
    uint16_t reserved2;
    uint64_t createTime;                /* Connection create time */
    uint32_t ownerModule;               /* Module that owns this */
    uint32_t reserved3;
    wchar_t processName[260];           /* Process name */
} NexusTcpConnection;

typedef struct NexusUdpEndpoint {
    uint32_t processId;                 /* Owner process ID */
    uint32_t reserved1;
    NexusIpAddress localAddress;        /* Local address */
    uint16_t localPort;                 /* Local port */
    uint16_t reserved2;
    uint64_t createTime;                /* Endpoint create time */
    uint32_t ownerModule;               /* Module that owns this */
    uint32_t flags;                     /* Endpoint flags */
    wchar_t processName[260];           /* Process name */
} NexusUdpEndpoint;

typedef struct NexusNetworkStats {
    uint32_t tcpConnectionCount;        /* Total TCP connections */
    uint32_t tcp6ConnectionCount;       /* IPv6 TCP connections */
    uint32_t udpEndpointCount;          /* Total UDP endpoints */
    uint32_t udp6EndpointCount;         /* IPv6 UDP endpoints */
    uint32_t listeningPorts;            /* Listening TCP ports */
    uint32_t establishedConnections;    /* Established TCP connections */
    uint64_t totalBytesSent;            /* Total bytes sent */
    uint64_t totalBytesReceived;        /* Total bytes received */
} NexusNetworkStats;

/* ============================================================================
 * TCP Connection Enumeration
 * ============================================================================ */

/**
 * Get all TCP connections.
 */
NEXUS_API NexusResult Nexus_NetGetTcpConnections(
    NexusTcpConnection* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get TCP connections for process.
 */
NEXUS_API NexusResult Nexus_NetGetTcpConnectionsForProcess(
    uint32_t processId,
    NexusTcpConnection* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get TCP connections by state.
 */
NEXUS_API NexusResult Nexus_NetGetTcpConnectionsByState(
    uint32_t state,
    NexusTcpConnection* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get TCP connections to remote address.
 */
NEXUS_API NexusResult Nexus_NetGetTcpConnectionsToAddress(
    const NexusIpAddress* remoteAddress,
    NexusTcpConnection* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get listening TCP ports.
 */
NEXUS_API NexusResult Nexus_NetGetListeningPorts(
    NexusTcpConnection* buffer,
    size_t bufferCount,
    size_t* count
);

/* ============================================================================
 * UDP Endpoint Enumeration
 * ============================================================================ */

/**
 * Get all UDP endpoints.
 */
NEXUS_API NexusResult Nexus_NetGetUdpEndpoints(
    NexusUdpEndpoint* buffer,
    size_t bufferCount,
    size_t* count
);

/**
 * Get UDP endpoints for process.
 */
NEXUS_API NexusResult Nexus_NetGetUdpEndpointsForProcess(
    uint32_t processId,
    NexusUdpEndpoint* buffer,
    size_t bufferCount,
    size_t* count
);

/* ============================================================================
 * Network Statistics
 * ============================================================================ */

/**
 * Get network statistics.
 */
NEXUS_API NexusResult Nexus_NetGetStats(
    NexusNetworkStats* stats
);

/**
 * Get network statistics for process.
 */
NEXUS_API NexusResult Nexus_NetGetStatsForProcess(
    uint32_t processId,
    NexusNetworkStats* stats
);

/* ============================================================================
 * Connection Operations
 * ============================================================================ */

/**
 * Close TCP connection (requires elevated privileges).
 */
NEXUS_API NexusResult Nexus_NetCloseTcpConnection(
    const NexusIpAddress* localAddress,
    uint16_t localPort,
    const NexusIpAddress* remoteAddress,
    uint16_t remotePort
);

/* ============================================================================
 * Address Utilities
 * ============================================================================ */

/**
 * Parse IP address from string.
 */
NEXUS_API NexusResult Nexus_NetParseAddress(
    const char* addressStr,
    NexusIpAddress* address
);

/**
 * Format IP address to string.
 */
NEXUS_API NexusResult Nexus_NetFormatAddress(
    const NexusIpAddress* address,
    char* buffer,
    size_t bufferSize
);

/**
 * Get TCP state as string.
 */
NEXUS_API const char* Nexus_NetGetTcpStateName(
    uint32_t state
);

/**
 * Resolve hostname to IP address.
 */
NEXUS_API NexusResult Nexus_NetResolveHostname(
    const char* hostname,
    NexusIpAddress* addresses,
    size_t maxAddresses,
    size_t* count
);

/**
 * Reverse lookup IP to hostname.
 */
NEXUS_API NexusResult Nexus_NetReverseLookup(
    const NexusIpAddress* address,
    char* hostname,
    size_t hostnameSize
);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_NETWORK_H */
