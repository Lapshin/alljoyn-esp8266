/**
 * @file
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h
 */

#define AJ_MODULE NET
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ets_sys.h>
#include <ip_addr.h>
#include <espconn.h>


#include <ajtcl/aj_target.h>
#include <ajtcl/aj_bufio.h>
#include <ajtcl/aj_net.h>
#include <ajtcl/aj_util.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_connect.h>
#include <ajtcl/aj_bus.h>
#include <ajtcl/aj_disco.h>
#include <ajtcl/aj_config.h>
#include <ajtcl/aj_std.h>

typedef struct {
    unsigned char counter;
    unsigned short len;
    uint8_t rxData[AJ_RX_DATA_SIZE];
} receivedBuff;

static receivedBuff global_rx_buffer;

/*
 * Need enough space to receive a complete name service packet when used in UDP
 * mode.  NS expects MTU of 1500 subtracts UDP, IP and ethertype overhead.
 * 1500 - 8 -20 - 18 = 1454.  txData buffer size needs to be big enough to hold
 * max(NS WHO-HAS for one name (4 + 2 + 256 = 262),
 *     mDNS query for one name (194 + 5 + 5 + 15 + 256 = 475)) = 475
 */
static uint8_t rxDataMCast[1454];
static uint8_t txDataMCast[475];

#ifdef AJ_ARDP
#include <ajtcl/aj_ardp.h>

static uint8_t rxDataARDP[AJ_RX_DATA_SIZE];
static uint8_t txDataARDP[AJ_TX_DATA_SIZE];
#endif

#ifdef AJ_TCP
static uint8_t rxDataTCP[AJ_RX_DATA_SIZE];
static uint8_t txDataTCP[AJ_TX_DATA_SIZE];
#endif

/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
#ifndef NDEBUG
uint8_t dbgNET = 0;
#endif

#define INVALID_SOCKET (-1)

/*
 * IANA assigned IPv4 multicast group for AllJoyn.
 */
//static const char AJ_IPV4_MULTICAST_GROUP[] = "224.0.0.113";
#define AJ_IPV4_MULTICAST_GROUP 0xE0000071

/*
 * IANA assigned UDP multicast port for AllJoyn
 */
#define AJ_UDP_PORT 9956

#if 0 //Now only multicast Alljoyn supported
/*
 * IANA-assigned IPv4 multicast group for mDNS.
 */
static const char MDNS_IPV4_MULTICAST_GROUP[] = "224.0.0.251";

/*
 * IANA-assigned UDP multicast port for mDNS
 */
#define MDNS_UDP_PORT 5353
#endif

/**
 * Target-specific contexts for network I/O
 */
#define MAX_SOCKETS 3
/*
 * 0 - ardp
 * 1 - tcp
 * 2 - udp
 *
 */
struct espconn sockets[MAX_SOCKETS];

static AJ_Status send_to_network(AJ_IOBuffer* buf)
{
    struct espconn *ctx;
    sint8 ret;
    size_t len;

    ctx = (struct espconn *) buf->context;
    len = AJ_IO_BUF_AVAIL(buf);

    if(len >= 0xFFFF) {
        return AJ_ERR_RESOURCES;
    } else if(len == 0) {
        return AJ_ERR_RESOURCES;
    }

    assert(buf->direction == AJ_IO_BUF_TX);

    global_rx_buffer.counter = 0;

    ret = espconn_sent(ctx, buf->readPtr, (uint16)len);
    if(ret != ESPCONN_OK) {
        return AJ_ERR_WRITE;
    }

    buf->readPtr += len;

    if (AJ_IO_BUF_AVAIL(buf) == 0) {
        AJ_IO_BUF_RESET(buf);
    }

    return AJ_OK;
}

static AJ_Status recieve_from_network(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    size_t rx;

    assert(buf->direction == AJ_IO_BUF_RX);

    rx = AJ_IO_BUF_SPACE(buf);
    rx = min(rx, len);
    if(rx == 0) {
        AJ_ErrPrintf(("CloseNetSock(): Nothing to receive!\n"));
        return AJ_OK;
    }

    if(global_rx_buffer.counter == 0) { //already received
        os_delay_us(timeout*1000);
    }

    if(global_rx_buffer.counter == 0) {
        return AJ_ERR_TIMEOUT;
    } else if (global_rx_buffer.counter > 1) {
        AJ_InfoPrintf(("recieve_from_network(): recv_callback calls %d times after sleep\n", global_rx_buffer.counter));
    }

    rx = min(rx, global_rx_buffer.len);
    memcpy(buf->writePtr, global_rx_buffer.rxData, rx);
    buf->writePtr += rx;
    global_rx_buffer.counter = 0;

    return AJ_OK;
}

static void dummy_callback(void *arg)
{
    return;
}

static data_recv_callback(void *arg, char *pdata, unsigned short len)
{
    if(len > AJ_RX_DATA_SIZE)
    {
        AJ_ErrPrintf(("data_ardp_recv_callback(): received big data (length %d)! Cut it!\n", len));
        len = AJ_RX_DATA_SIZE;
    }
//    memset(global_rx_buffer.rxData, 0, AJ_RX_DATA_SIZE);
    memcpy(global_rx_buffer.rxData, pdata, len);
    global_rx_buffer.counter++;
    global_rx_buffer.len = len;
    return;
}

#ifdef AJ_ARDP
/**
 * Need to predeclare a few things for ARDP
 */
static AJ_Status AJ_Net_ARDP_Connect(AJ_BusAttachment* bus, const AJ_Service* service);
static void AJ_Net_ARDP_Disconnect(AJ_NetSocket* netSock);

#endif // AJ_ARDP

#ifdef AJ_TCP

static void connect_callback(void *arg)
{
    struct espconn *pespconn = arg;
    espconn_regist_recvcb(pespconn, data_recv_callback);
    espconn_regist_sentcb(pespconn, dummy_callback);
    espconn_regist_write_finish(pespconn, dummy_callback);
    espconn_regist_disconcb(pespconn, dummy_callback);
    return;
}

static AJ_Status CloseNetSock(AJ_NetSocket* netSock)
{
    struct espconn *ctx;
    AJ_Status status = AJ_OK;

    ctx = (struct espconn*) netSock->rx.context;

    if (ctx->type == ESPCONN_TCP) {
        espconn_disconnect((struct espconn *) ctx);
        os_free(ctx->proto.tcp);
    } else if(ctx->type == ESPCONN_UDP) {
        AJ_ErrPrintf(("CloseNetSock(): Bad socket type %d!\n", ctx->type));
        status = AJ_ERR_INVALID;
    }

    memset(ctx, 0, sizeof(struct espconn));
    memset(netSock, 0, sizeof(AJ_NetSocket));

    return status;
}

AJ_Status AJ_Net_Send(AJ_IOBuffer* buf)
{
    return send_to_network(buf);
}

AJ_Status AJ_Net_Recv(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    return recieve_from_network(buf, len, timeout);
}

static AJ_Status AJ_TCP_Connect(AJ_BusAttachment* bus, const AJ_Service* service)
{
    int ret;
    struct espconn *ctx;
    esp_tcp *tcp;

    ctx = &sockets[1];

    if ((service->addrTypes & AJ_ADDR_TCP4) != AJ_ADDR_TCP4) {
        AJ_ErrPrintf(("AJ_TCP_Connect(): Invalid addrTypes %u, status=AJ_ERR_CONNECT\n", service->addrTypes));
        return AJ_ERR_CONNECT;
    }

    ctx->type = ESPCONN_TCP;
    ctx->state = ESPCONN_CONNECT;

    tcp = (esp_tcp *)os_zalloc(sizeof(esp_tcp));
    if (tcp == NULL) {
        return AJ_ERR_CONNECT;
    }

    tcp->remote_port = service->ipv4port;
    tcp->local_port = service->ipv4port;

    //TODO: get from memory. Use wifi_get_ip_info!
    tcp->local_ip[0] = 192;
    tcp->local_ip[1] = 168;
    tcp->local_ip[2] = 1;
    tcp->local_ip[3] = 69;

    memcpy((void *)&tcp->remote_ip[0], (void *)service->ipv4, sizeof(tcp->remote_ip));
    ctx->proto.tcp = tcp;

    espconn_regist_connectcb(ctx, connect_callback);
    espconn_regist_reconcb(ctx, dummy_callback);

    AJ_InfoPrintf(("AJ_TCP_Connect(): Connect to \"%s:%u\"\n", inet_ntoa(service->ipv4), service->ipv4port));

    ret = espconn_connect(ctx);
    if (ret != ESPCONN_OK) {
        AJ_ErrPrintf(("AJ_TCP_Connect(): connect() failed. error=\"%d\", status=AJ_ERR_CONNECT\n", ret));
        return AJ_ERR_CONNECT;
    } else {
        AJ_IOBufInit(&bus->sock.rx, rxDataTCP, sizeof(rxDataTCP), AJ_IO_BUF_RX, ctx);
        bus->sock.rx.recv = AJ_Net_Recv;
        AJ_IOBufInit(&bus->sock.tx, txDataTCP, sizeof(txDataTCP), AJ_IO_BUF_TX, ctx);
        bus->sock.tx.send = AJ_Net_Send;
        AJ_InfoPrintf(("AJ_TCP_Connect(): status=AJ_OK\n"));
    }

    return AJ_OK;
}
#endif


AJ_Status AJ_Net_Connect(AJ_BusAttachment* bus, const AJ_Service* service)
{
    AJ_Status status = AJ_ERR_CONNECT;

    AJ_InfoPrintf(("AJ_Net_Connect(bus=0x%p, addrType=%d.)\n", bus, service->addrTypes));

#ifdef AJ_ARDP
    if (service->addrTypes & (AJ_ADDR_UDP4 | AJ_ADDR_UDP6)) {
        status = AJ_Net_ARDP_Connect(bus, service);
        if (status == AJ_OK) {
            return status;
        }
    }
#endif

#ifdef AJ_TCP
    if (service->addrTypes & (AJ_ADDR_TCP4 | AJ_ADDR_TCP6)) {
        status = AJ_TCP_Connect(bus, service);
    }
#endif

    return status;
}

void AJ_Net_Disconnect(AJ_NetSocket* netSock)
{
#ifdef AJ_ARDP
        // we are using UDP!
        AJ_Net_ARDP_Disconnect(netSock);
        memset(netSock, 0, sizeof(AJ_NetSocket));
#endif
#ifdef AJ_TCP
        CloseNetSock(netSock);
#endif
}

AJ_Status AJ_Net_SendTo(AJ_IOBuffer* buf)
{
    if((((struct espconn*)buf->context)->type == ESPCONN_UDP) && (buf->flags & AJ_IO_BUF_AJ)) {
        return send_to_network(buf);
    } else {
        AJ_ErrPrintf(("AJ_Net_SendTo(): Bad buff! Type (%d) flags (%d)\n",
                ((struct espconn*)buf->context)->type,
                buf->flags & AJ_IO_BUF_AJ));
        return AJ_ERR_WRITE;
    }
}

AJ_Status AJ_Net_RecvFrom(AJ_IOBuffer* buf, uint32_t len, uint32_t timeout)
{
    return recieve_from_network(buf, len, timeout);
}

AJ_Status AJ_Net_MCastUp(AJ_MCastSocket* mcastSock)
{
    sint8 ret;
    struct espconn *ctx;
    esp_udp *udp;
    uint32_t ip_local, ip_mcast;

    ip_local = 0xC0A80145;
    ip_mcast = AJ_IPV4_MULTICAST_GROUP;

    ctx = &sockets[2];

    ctx->type = ESPCONN_UDP;
    ctx->state = ESPCONN_NONE;

    udp = (esp_udp *)os_zalloc(sizeof(esp_udp));
    if (udp == NULL) {
        AJ_ErrPrintf(("AJ_Net_MCastUp(): Error while allocate\n"));
        return AJ_ERR_RESOURCES;
    }

    udp->remote_port = AJ_UDP_PORT;
    udp->local_port = AJ_UDP_PORT;

    //TODO: it must be zeroed?
    udp->local_ip[0] = 0;
    udp->local_ip[1] = 0;
    udp->local_ip[2] = 0;
    udp->local_ip[3] = 0;

    memcpy((void *)&udp->remote_ip[0], (void *)&ip_mcast, sizeof(udp->remote_ip));
    ctx->proto.udp = udp;

    espconn_regist_recvcb(ctx, data_recv_callback);
    espconn_regist_sentcb(ctx, dummy_callback);

    ret = espconn_create(ctx);

    if (ret != ESPCONN_OK) {
        AJ_ErrPrintf(("AJ_Net_MCastUp(): Error connecting\n"));
        return AJ_ERR_CONNECT;
    }

    espconn_igmp_join(&ip_local, &ip_mcast);

    AJ_IOBufInit(&mcastSock->rx, rxDataMCast, sizeof(rxDataMCast), AJ_IO_BUF_RX, ctx);
    mcastSock->rx.recv = AJ_Net_RecvFrom;
    AJ_IOBufInit(&mcastSock->tx, txDataMCast, sizeof(txDataMCast), AJ_IO_BUF_TX, ctx);
    mcastSock->tx.send = AJ_Net_SendTo;

    return AJ_OK;
}

void AJ_Net_MCastDown(AJ_MCastSocket* mcastSock)
{
    struct espconn* ctx;
    ctx = (struct espconn*) mcastSock->rx.context;
    AJ_InfoPrintf(("AJ_Net_MCastDown(mcastSock=0x%p)\n", mcastSock));

    if (ctx->type == ESPCONN_UDP) {
        espconn_disconnect(ctx);
        os_free(ctx->proto.udp);
    } else {
        AJ_ErrPrintf(("AJ_Net_MCastDown(): Bad socket type %d!\n", ctx->type));
    }

    memset(ctx, 0, sizeof(struct espconn));
    memset(mcastSock, 0, sizeof(AJ_MCastSocket));
}

#ifdef AJ_ARDP

static AJ_Status AJ_ARDP_UDP_Send(void* context, uint8_t* buf, size_t len, size_t* sent, uint8_t confirm)
{
    struct espconn *ctx;
    sint8 ret;

    ctx = (struct espconn *) context;

    if(len >= 0xFFFF) {
        return AJ_ERR_RESOURCES;
    } else if (len == 0) {
        return AJ_OK;
    }

    global_rx_buffer.counter = 0;

    ret = espconn_sent(ctx, buf, (uint16)len);
    if(ret != ESPCONN_OK) {
        return AJ_ERR_WRITE;
    }

    *sent = len;

    return AJ_OK;
}

static AJ_Status AJ_ARDP_UDP_Recv(void* context, uint8_t** data, uint32_t* recved, uint32_t timeout)
{
    static uint8_t buffer[UDP_SEGBMAX];

    *data = NULL;

    if(global_rx_buffer.counter == 0) { //already received
        os_delay_us(timeout*1000);
    }

    if(global_rx_buffer.counter == 0) {
        return AJ_ERR_TIMEOUT;
    } else if (global_rx_buffer.counter > 1) {
        AJ_InfoPrintf(("AJ_ARDP_UDP_Recv(): recv_callback calls %d times after sleep\n", global_rx_buffer.counter));
    }

    memcpy(buffer, global_rx_buffer.rxData, global_rx_buffer.len);
    *data = buffer;
    *recved = global_rx_buffer.len;
    global_rx_buffer.counter = 0;

    return AJ_OK;
}

static AJ_Status AJ_Net_ARDP_Connect(AJ_BusAttachment* bus, const AJ_Service* service)
{
    AJ_Status status;
    sint8 ret;
    struct espconn *ctx;
    esp_udp *udp;

    ctx = &sockets[0];

    AJ_ARDP_InitFunctions(AJ_ARDP_UDP_Recv, AJ_ARDP_UDP_Send);

    if ((service->addrTypes & AJ_ADDR_UDP4) != AJ_ADDR_UDP4) {
        AJ_ErrPrintf(("AJ_Net_ARDP_Connect(): Invalid addrTypes %u, status=AJ_ERR_CONNECT\n", service->addrTypes));
        return AJ_ERR_CONNECT;
    }

    ctx->type = ESPCONN_UDP;
    ctx->state = ESPCONN_NONE;

    udp = (esp_udp *)os_zalloc(sizeof(esp_udp));
    if (udp == NULL) {
        AJ_ErrPrintf(("AJ_Net_ARDP_Connect(): Error while allocate\n"));
        return AJ_ERR_RESOURCES;
    }

    udp->remote_port = service->ipv4portUdp;
    udp->local_port = service->ipv4portUdp;

    //TODO: get from memory. Use wifi_get_ip_info!
    udp->local_ip[0] = 192;
    udp->local_ip[1] = 168;
    udp->local_ip[2] = 1;
    udp->local_ip[3] = 69;

    memcpy((void *)&udp->remote_ip[0], (void *)service->ipv4Udp, sizeof(udp->remote_ip));
    ctx->proto.udp = udp;

    espconn_regist_recvcb(ctx, data_recv_callback);
    espconn_regist_sentcb(ctx, dummy_callback);

    ret = espconn_create(ctx);

    // must do this before calling AJ_MarshalMethodCall!
    if (ret != ESPCONN_OK) {
        AJ_ErrPrintf(("AJ_Net_ARDP_Connect(): Error connecting\n"));
        return AJ_ERR_CONNECT;
    }

    AJ_IOBufInit(&bus->sock.rx, rxDataARDP, sizeof(rxDataARDP), AJ_IO_BUF_RX, ctx);
    bus->sock.rx.recv = AJ_ARDP_Recv;
    AJ_IOBufInit(&bus->sock.tx, txDataARDP, sizeof(txDataARDP), AJ_IO_BUF_TX, ctx);
    bus->sock.tx.send = AJ_ARDP_Send;

    status = AJ_ARDP_UDP_Connect(bus, ctx, service, &bus->sock);
    if (status != AJ_OK) {
        AJ_Net_ARDP_Disconnect(&bus->sock);
        return AJ_ERR_CONNECT;
    }

    return AJ_OK;
}

static void AJ_Net_ARDP_Disconnect(AJ_NetSocket* netSock)
{
    struct espconn* ctx;
    ctx = (struct espconn*) netSock->rx.context;

    AJ_ARDP_Disconnect(FALSE);

    if (ctx->type == ESPCONN_UDP) {
        espconn_disconnect(ctx);
        os_free(ctx->proto.udp);
    } else {
        AJ_ErrPrintf(("AJ_Net_ARDP_Disconnect(): Bad socket type %d!\n", ctx->type));
    }

    memset(ctx, 0, sizeof(struct espconn));
    memset(netSock, 0, sizeof(AJ_NetSocket));
}

#endif // AJ_ARDP
