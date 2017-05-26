/*
 * Copyright (c) 2016, CESAR.
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license. See the LICENSE file for details.
 *
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#ifdef ARDUINO
#include "hal/avr_errno.h"
#include "hal/avr_unistd.h"
#include "src/hal/sec/security_ino.h"
#else
#include <errno.h>
#include <unistd.h>
#include "src/hal/sec/security.h"
#endif

#include "hal/nrf24.h"
#include "hal/comm.h"
#include "hal/time.h"
#include "hal/config.h"
#include "phy_driver.h"
#include "phy_driver_nrf24.h"
#include "nrf24l01_ll.h"

#define _MIN(a, b)		((a) < (b) ? (a) : (b))
#define DATA_SIZE 128
#define MGMT_SIZE 32
#define MGMT_TIMEOUT 10
#define RAW_TIMEOUT 60

/* secret key and auxiliar buffer*/
uint8_t bytebuffer[48];
uint8_t skey[32];
uint8_t iv = 0x00;

uint8_t private_4[NUM_ECC_DIGITS] = {0xA3, 0xB0, 0x24, 0xBB, 0xA9, \
	0xA2, 0xC2, 0xC0, 0xB2, 0xE6, 0xEB, 0x32, 0xF7, 0x40, 0xF3, 0xD7, \
	0xB6, 0xFA, 0x27, 0x2F, 0xA8, 0x09, 0xE7, 0x6D, 0xF7, 0x7F, 0xF8, \
	0xB5, 0x7F, 0x0D, 0xDF, 0xBE};
uint8_t public_4x[NUM_ECC_DIGITS] = {0x03, 0x7A, 0xDC, 0x3D, 0x4C, \
	0x9D, 0xDD, 0x77, 0xA8, 0xC2, 0x65, 0x5C, 0xA0, 0xE8, 0xCC, 0x51, \
	0xA7, 0x21, 0x6B, 0xD1, 0x9A, 0x4A, 0xA3, 0x55, 0x71, 0xAC, 0x2A, \
	0x72, 0xFE, 0x9C, 0xE6, 0x06};
uint8_t public_4y[NUM_ECC_DIGITS] = {0x96, 0x3F, 0x32, 0x1B, 0x42, 0x1D, \
	0xE1, 0x47, 0x3D, 0xA5, 0xE8, 0x57, 0xDF, 0xBA, 0x09, 0xF2, 0xB0, 0x2E, \
	0xEF, 0x79, 0xD0, 0x31, 0xF1, 0xCD, 0xDB, 0x17, 0x70, 0x08, 0xC3, 0x37, \
	0x7E, 0x84};
// public stranger key
uint8_t public_3x[NUM_ECC_DIGITS] = {0x8C, 0xDC, 0xCF, 0xD4, 0xCD, 0x34, \
	0x3F, 0x9B, 0x0D, 0x70, 0x57, 0x3D, 0x40, 0x1A, 0x6F, 0xFE, 0xB0, 0x9C, \
	0x05, 0x47, 0xE4, 0x02, 0x8C, 0xAF, 0x0C, 0x2D, 0xDB, 0x8A, 0xC9, 0x66, \
	0x37, 0x1F};
uint8_t public_3y[NUM_ECC_DIGITS] = {0xF4, 0x60, 0xB9, 0x86, 0x5A, 0xC5, \
	0xB0, 0x41, 0xF9, 0x53, 0x18, 0xCF, 0x9A, 0x7B, 0x24, 0xF8, 0x75, 0x94, \
	0xD9, 0xEF, 0x49, 0xC1, 0x9A, 0xAE, 0xE4, 0xE5, 0x64, 0xAD, 0x58, 0x48, \
	0x6D, 0x36};

#define SET_BIT(val, idx)	((val) |= 1 << (idx))
#define CLR_BIT(val, idx)	((val) &= ~(1 << (idx)))
#define CHK_BIT(val, idx)      ((val) & (1 << (idx)))

/* Global to know if listen function was called */
static uint8_t listen = 0;

/*
 * Bitmask to track assigned pipes.
 *
 * 0000 0001: pipe0
 * 0000 0010: pipe1
 * 0000 0100: pipe2
 * 0000 1000: pipe3
 * 0001 0000: pipe4
 * 0010 0000: pipe5
 */
#define PIPE_RAW_BITMASK	0b00111110 /* Map of RAW Pipes */

static uint8_t pipe_bitmask = 0b00000001; /* Default: scanning/broadcasting */

static struct nrf24_mac mac_local = {.address.uint64 = 0 };

/* Structure to save broadcast context */
struct nrf24_mgmt {
	int8_t pipe;
	uint8_t buffer_rx[MGMT_SIZE];
	size_t len_rx;
	uint8_t buffer_tx[MGMT_SIZE];
	size_t len_tx;
};

static struct nrf24_mgmt mgmt = {.pipe = -1, .len_rx = 0};

/* Structure to save peers context */
struct nrf24_data {
	int8_t pipe;
	uint8_t buffer_rx[DATA_SIZE];
	size_t len_rx;
	uint8_t buffer_tx[DATA_SIZE];
	size_t len_tx;
	uint8_t seqnumber_tx;
	uint8_t seqnumber_rx;
	size_t offset_rx;
	unsigned long keepalive_anchor; /* Last packet received */
	uint8_t keepalive; /* zero: disabled or positive: window attempts */
	struct nrf24_mac mac;
};

#ifndef ARDUINO	/* If master then 5 peers */
static struct nrf24_data peers[5] = {
	{.pipe = -1, .len_rx = 0, .seqnumber_tx = 0,
		.seqnumber_rx = 0, .offset_rx = 0},
	{.pipe = -1, .len_rx = 0, .seqnumber_tx = 0,
		.seqnumber_rx = 0, .offset_rx = 0},
	{.pipe = -1, .len_rx = 0, .seqnumber_tx = 0,
		.seqnumber_rx = 0, .offset_rx = 0},
	{.pipe = -1, .len_rx = 0, .seqnumber_tx = 0,
		.seqnumber_rx = 0, .offset_rx = 0},
	{.pipe = -1, .len_rx = 0, .seqnumber_tx = 0,
		.seqnumber_rx = 0, .offset_rx = 0}
};
#else	/* If slave then 1 peer */
static struct nrf24_data peers[1] = {
	{.pipe = -1, .len_rx = 0, .seqnumber_tx = 0,
		.seqnumber_rx = 0, .offset_rx = 0},
};
#endif

/* ARRAY SIZE */
#define CONNECTION_COUNTER	((int) (sizeof(peers) \
				 / sizeof(peers[0])))

/*
 * TODO: Get this values from config file
 * Access Address for each pipe
 */
static uint8_t aa_pipe0[5] = {0x8D, 0xD9, 0xBE, 0x96, 0xDE};

/* Global to save driver index */
static int driverIndex = -1;

/*
 * Channel to management and raw data
 *
 * nRF24 channels has been selected to avoid common interference sources:
 * Wi-Fi channels (1, 6 and 11) and Bluetooth adversiting channels (37,
 * 38 and 39). Suggested nRF24 channels are channels 22 (2422 MHz), 50
 * (2450 MHz), 74 (2474 MHz), 76 (2476 MHz) and 97 (2497 MHz).
 */
static int channel_mgmt = 76;
static int channel_raw = 22;

static uint16_t window_bcast = 5;	/* ms */
static uint16_t interval_bcast = 6;	/* ms */

enum {
	START_MGMT,
	MGMT,
	START_RAW,
	RAW
};

enum {
	PRESENCE,
	TIMEOUT_WINDOW,
	STANDBY,
	TIMEOUT_INTERVAL
};

/* Local functions */
static inline int alloc_pipe(void)
{
	uint8_t i;

	for (i = 0; i < CONNECTION_COUNTER; i++) {
		if (peers[i].pipe == -1) {
			/* Peers initialization */
			memset(&peers[i], 0, sizeof(peers[i]));
			/* One peer for pipe*/
			peers[i].pipe = i+1;
			SET_BIT(pipe_bitmask, peers[i].pipe);
			return peers[i].pipe;
		}
	}

	/* No free pipe */
	return -1;
}

static int write_disconnect(int spi_fd, int sockfd, struct nrf24_mac dst,
				struct nrf24_mac src)
{
	struct nrf24_io_pack p;
	struct nrf24_ll_data_pdu *opdu =
		(struct nrf24_ll_data_pdu *) p.payload;
	struct nrf24_ll_crtl_pdu *llctrl =
		(struct nrf24_ll_crtl_pdu *) opdu->payload;
	struct nrf24_ll_disconnect *lldc =
		(struct nrf24_ll_disconnect *) llctrl->payload;
	int err;

	opdu->lid = NRF24_PDU_LID_CONTROL;
	p.pipe = sockfd;
	llctrl->opcode = NRF24_LL_CRTL_OP_DISCONNECT;
	lldc->dst_addr.address.uint64 = dst.address.uint64;
	lldc->src_addr.address.uint64 = src.address.uint64;
	err = phy_write(spi_fd, &p,
					sizeof(struct nrf24_ll_data_pdu) +
					sizeof(struct nrf24_ll_crtl_pdu) +
					sizeof(struct nrf24_ll_disconnect));

	if (err < 0)
		return err;

	return 0;
}

static int write_keepalive(int spi_fd, int sockfd, int keepalive_op,
				struct nrf24_mac dst, struct nrf24_mac src)
{
	int err;
	uint8_t *cdata;
	size_t block, size;
	/* Assemble keep alive packet */
	struct nrf24_io_pack p;
	struct nrf24_ll_data_pdu *opdu =
		(struct nrf24_ll_data_pdu *) p.payload;
	struct nrf24_ll_crtl_pdu *llctrl =
		(struct nrf24_ll_crtl_pdu *) opdu->payload;
	struct nrf24_ll_keepalive *llkeepalive =
		(struct nrf24_ll_keepalive *) llctrl->payload;

	opdu->lid = NRF24_PDU_LID_CONTROL;
	p.pipe = sockfd;
	/* Keep alive opcode - Request or Response */
	llctrl->opcode = keepalive_op;
	/* src and dst address to keepalive */
	llkeepalive->dst_addr.address.uint64 = dst.address.uint64;
	llkeepalive->src_addr.address.uint64 = src.address.uint64;
		
	size = sizeof(struct nrf24_ll_data_pdu) +
 					sizeof(struct nrf24_ll_crtl_pdu) +
					sizeof(struct nrf24_ll_keepalive);

	/* Encrypt Data */
	cdata = p.payload + 2;

	//Force block size to 16 or 32
	if (size > 16)
		block = 32;
	else
		block = 16;

	derive_secret (public_3x, public_3y, private_4,
					public_4x, public_4y, skey, 0);

	err = encrypt(cdata, block, skey, &iv);

	if (err < 0)
		return err;

	size = err;

	/*End of Encryption*/

	/* Sends keep alive packet */
	err = phy_write(spi_fd, &p, sizeof(*opdu) + sizeof(*llctrl) +
							sizeof(*llkeepalive));
	if (err < 0)
		return err;

	return 0;
}

static int check_keepalive(int spi_fd, int sockfd)
{
	uint32_t time_ms = hal_time_ms();

	/* Check if timeout occurred */
	if (hal_timeout(time_ms, peers[sockfd-1].keepalive_anchor,
						NRF24_KEEPALIVE_TIMEOUT_MS) > 0)
		return -ETIMEDOUT;

	if (peers[sockfd-1].keepalive == 0)
		return 0;

	if (hal_timeout(time_ms, peers[sockfd-1].keepalive_anchor,
		peers[sockfd-1].keepalive * NRF24_KEEPALIVE_SEND_MS) <= 0)
		return 0;

	peers[sockfd-1].keepalive++;

	/* Sends keepalive packet */
	return write_keepalive(spi_fd, sockfd,
			      NRF24_LL_CRTL_OP_KEEPALIVE_REQ,
			      peers[sockfd-1].mac, mac_local);
}

static int write_mgmt(int spi_fd)
{
	int err;
	struct nrf24_io_pack p;

	/* If nothing to do */
	if (mgmt.len_tx == 0)
		return -EAGAIN;

	/* Set pipe to be sent */
	p.pipe = 0;
	/* Copy buffer_tx to payload */
	memcpy(p.payload, mgmt.buffer_tx, mgmt.len_tx);

	err = phy_write(spi_fd, &p, mgmt.len_tx);
	if (err < 0)
		return err;

	/* Reset len_tx */
	mgmt.len_tx = 0;

	return err;
}

static int read_mgmt(int spi_fd)
{
	struct nrf24_io_pack p;
	struct nrf24_ll_mgmt_pdu *ipdu = (struct nrf24_ll_mgmt_pdu *)p.payload;
	struct mgmt_evt_nrf24_bcast_presence *mgmtev_bcast;
	struct mgmt_evt_nrf24_connected *mgmtev_cn;
	struct mgmt_nrf24_header *mgmtev_hdr;
	struct nrf24_ll_mgmt_connect *llc;
	struct nrf24_ll_presence *llp;
	ssize_t ilen;

	/* Read from management pipe */
	p.pipe = 0;
	p.payload[0] = 0;
	/* Read data */
	ilen = phy_read(spi_fd, &p, NRF24_MTU);
	if (ilen < 0)
		return -EAGAIN;

	/* If already has something in rx buffer then return BUSY */
	if (mgmt.len_rx != 0)
		return -EBUSY;

	/* Event header structure */
	mgmtev_hdr = (struct mgmt_nrf24_header *) mgmt.buffer_rx;

	switch (ipdu->type) {
	/* If is a presente type */
	case NRF24_PDU_TYPE_PRESENCE:

		if (ilen < (ssize_t) (sizeof(struct nrf24_ll_mgmt_pdu) +
					sizeof(struct nrf24_ll_presence)))
			return -EINVAL;

		/* Event presence structure */
		mgmtev_bcast = (struct mgmt_evt_nrf24_bcast_presence *)mgmtev_hdr->payload;
		/* Presence structure */
		llp = (struct nrf24_ll_presence *) ipdu->payload;

		/* Header type is a broadcast presence */
		mgmtev_hdr->opcode = MGMT_EVT_NRF24_BCAST_PRESENCE;
		mgmtev_hdr->index = 0;
		/* Copy source address */
		mgmtev_bcast->mac.address.uint64 = llp->mac.address.uint64;
		/*
		 * The packet structure contains the
		 * mgmt_pdu header, the MAC address
		 * and the slave name. The name length
		 * is equal to input length (ilen) minus
		 * header length and minus MAC address length.
		 */
		memcpy(mgmtev_bcast->name, llp->name,
				ilen - sizeof(*llp) - sizeof(*ipdu));

		/*
		 * The rx buffer length is equal to the
		 * event header length + presence packet length.
		 * Presence packet len = (input len - mgmt_pdu header len)
		 */
		mgmt.len_rx = ilen - sizeof(*ipdu) + sizeof(*mgmtev_hdr);

		break;
	/* If is a connect request type */
	case NRF24_PDU_TYPE_CONNECT_REQ:

		if (ilen != (sizeof(struct nrf24_ll_mgmt_pdu) +
			     sizeof(struct nrf24_ll_mgmt_connect)))
			return -EINVAL;

		/* Event connect structure */
		mgmtev_cn = (struct mgmt_evt_nrf24_connected *)mgmtev_hdr->payload;
		/* Link layer connect structure */
		llc = (struct nrf24_ll_mgmt_connect *) ipdu->payload;

		/* Header type is a connect request type */
		mgmtev_hdr->opcode = MGMT_EVT_NRF24_CONNECTED;
		mgmtev_hdr->index = 0;
		/* Copy src and dst address*/
		mgmtev_cn->src.address.uint64 = llc->src_addr.address.uint64;
		mgmtev_cn->dst.address.uint64 = llc->dst_addr.address.uint64;
		/* Copy channel */
		mgmtev_cn->channel = llc->channel;
		/* Copy access address */
		memcpy(mgmtev_cn->aa, llc->aa, sizeof(mgmtev_cn->aa));

		mgmt.len_rx = sizeof(*mgmtev_hdr) + sizeof(*mgmtev_cn);

		break;
	default:
		return -EINVAL;
	}

	/* Returns the amount of bytes read */
	return ilen;
}

static int write_raw(int spi_fd, int sockfd)
{
	int err;
	struct nrf24_io_pack p;
	struct nrf24_ll_data_pdu *opdu = (void *)p.payload;
	size_t plen, left, block;
	uint8_t *cdata;

	/* If has nothing to send, returns EBUSY */
	if (peers[sockfd-1].len_tx == 0)
		return -EAGAIN;

	/* If len is larger than the maximum message size */
	if (peers[sockfd-1].len_tx > DATA_SIZE)
		return -EINVAL;

	/* Set pipe to be sent */
	p.pipe = sockfd;
	/* Amount of bytes to be sent */
	left = peers[sockfd-1].len_tx;

	while (left) {

		/* Delay to avoid sending all packets too fast */
		hal_delay_us(512);
		/*
		 * If left is larger than the NRF24_PW_MSG_SIZE,
		 * payload length = NRF24_PW_MSG_SIZE,
		 * if not, payload length = left
		 */
		plen = _MIN(left, NRF24_PW_MSG_SIZE);

		/*
		 * If left is larger than the NRF24_PW_MSG_SIZE,
		 * it means that the packet is fragmented,
		 * if not, it means that it is the last packet.
		 */
		opdu->lid = (left > NRF24_PW_MSG_SIZE) ?
			NRF24_PDU_LID_DATA_FRAG : NRF24_PDU_LID_DATA_END;

		/* Packet sequence number */
		opdu->nseq = peers[sockfd-1].seqnumber_tx;

		/* Offset = len - left */
		memcpy(opdu->payload, peers[sockfd-1].buffer_tx +
			(peers[sockfd-1].len_tx - left), plen);

		/*Encrypt Data*/
		//Force block size to 16 or 32
		if (plen > 16)
			block = 32;
		else
			block = 16;
		
		cdata = p.payload + 2;

		derive_secret (public_3x, public_3y, private_4,
						public_4x, public_4y, skey, 0);
		
		err = encrypt(cdata, block, skey, &iv);
		
		if (err < 0)
			return err;
		
		plen = err;

		/*End of Encryption*/

		/* Send packet */
		err = phy_write(spi_fd, &p, plen + DATA_HDR_SIZE);
		/*
		 * If write error then reset tx len
		 * and sequence number
		 */
		if (err < 0) {
			peers[sockfd-1].len_tx = 0;
			peers[sockfd-1].seqnumber_tx = 0;
			return err;
		}

		left -= plen;
		peers[sockfd-1].seqnumber_tx++;
	}

	err = peers[sockfd-1].len_tx;

	/* Resets controls */
	peers[sockfd-1].len_tx = 0;
	peers[sockfd-1].seqnumber_tx = 0;

	return err;
}

static int read_raw(int spi_fd, int sockfd)
{
	struct nrf24_io_pack p;
	const struct nrf24_ll_data_pdu *ipdu = (void *) p.payload;
	struct mgmt_nrf24_header *mgmtev_hdr;
	struct mgmt_evt_nrf24_disconnected *mgmtev_dc;
	struct nrf24_ll_disconnect *lldc;
	struct nrf24_ll_keepalive *llkeepalive;
	struct nrf24_ll_crtl_pdu *llctrl;
	size_t plen;
	ssize_t ilen, block;
	int size;
	uint8_t *cdata;

	p.pipe = sockfd;
	p.payload[0] = 0;
	/*
	 * Reads the data while to exist,
	 * on success, the number of bytes read is returned
	 */
	while ((ilen = phy_read(spi_fd, &p, NRF24_MTU)) > 0) {

		/* Initiator/acceptor: reset anchor */
		peers[sockfd-1].keepalive_anchor = hal_time_ms();

		/*Decrypt Data here*/
		cdata = p.payload+2;
		size = ilen - DATA_HDR_SIZE;

		//Force block size to 16 or 32
		if (size > 16)
			block = 32;
		else
			block = 16;

		derive_secret (public_3x, public_3y, private_4,
					public_4x, public_4y, skey, &iv);
		
		size = decrypt(cdata, block, skey, 0);
		
		//size act as err
		if (size < 0)
			return size;

		/*End of Decryption*/

		/* Check if is data or Control */
		switch (ipdu->lid) {

		/* If is Control */
		case NRF24_PDU_LID_CONTROL:
			llctrl = (struct nrf24_ll_crtl_pdu *)ipdu->payload;
			llkeepalive = (struct nrf24_ll_keepalive *)
							llctrl->payload;
			lldc = (struct nrf24_ll_disconnect *) llctrl->payload;

			if (llctrl->opcode == NRF24_LL_CRTL_OP_KEEPALIVE_REQ &&
				llkeepalive->src_addr.address.uint64 ==
				peers[sockfd-1].mac.address.uint64 &&
				llkeepalive->dst_addr.address.uint64 ==
				mac_local.address.uint64) {
				write_keepalive(spi_fd, sockfd,
					NRF24_LL_CRTL_OP_KEEPALIVE_RSP,
					peers[sockfd-1].mac,
					mac_local);
			} else if (llctrl->opcode == NRF24_LL_CRTL_OP_KEEPALIVE_RSP) {
				/* Resets the counter */
				peers[sockfd-1].keepalive = 1;
			}

			/* If packet is disconnect request */
			else if (llctrl->opcode == NRF24_LL_CRTL_OP_DISCONNECT &&
							mgmt.len_rx == 0) {
				mgmtev_hdr = (struct mgmt_nrf24_header *)
								mgmt.buffer_rx;
				mgmtev_dc = (struct mgmt_evt_nrf24_disconnected *)
							mgmtev_hdr->payload;

				mgmtev_hdr->opcode = MGMT_EVT_NRF24_DISCONNECTED;
				mgmtev_dc->mac.address.uint64 =
					lldc->src_addr.address.uint64;
				mgmt.len_rx = sizeof(*mgmtev_hdr) +
							sizeof(*mgmtev_dc);
			}

			break;
		/* If is Data */
		case NRF24_PDU_LID_DATA_FRAG:
		case NRF24_PDU_LID_DATA_END:
			if (peers[sockfd-1].len_rx != 0)
				break; /* Discard packet */

			/* Reset offset if sequence number is zero */
			if (ipdu->nseq == 0) {
				peers[sockfd-1].offset_rx = 0;
				peers[sockfd-1].seqnumber_rx = 0;
			}

			/* If sequence number error */
			if (peers[sockfd-1].seqnumber_rx < ipdu->nseq)
				break;
				/*
				 * TODO: disconnect, data error!?!?!?
				 * Illegal byte sequence
				 */

			if (peers[sockfd-1].seqnumber_rx > ipdu->nseq)
				break; /* Discard packet duplicated */

			/* Payloag length = input length - header size */
			plen = ilen - DATA_HDR_SIZE;

			if (ipdu->lid == NRF24_PDU_LID_DATA_FRAG &&
				plen < NRF24_PW_MSG_SIZE)
				break;
				/*
				 * TODO: disconnect, data error!?!?!?
				 * Not a data message
				 */

			/* Reads no more than DATA_SIZE bytes */
			if (peers[sockfd-1].offset_rx + plen > DATA_SIZE)
				plen = DATA_SIZE - peers[sockfd-1].offset_rx;

			memcpy(peers[sockfd-1].buffer_rx +
				peers[sockfd-1].offset_rx, ipdu->payload, plen);
			peers[sockfd-1].offset_rx += plen;
			peers[sockfd-1].seqnumber_rx++;

			/* If is DATA_END then put in rx buffer */
			if (ipdu->lid == NRF24_PDU_LID_DATA_END) {
				/* Sets packet length read */
				peers[sockfd-1].len_rx =
					peers[sockfd-1].offset_rx;

				/*
				 * If the complete msg is received,
				 * resets the controls
				 */
				peers[sockfd-1].seqnumber_rx = 0;
				peers[sockfd-1].offset_rx = 0;
			}
			break;
		}
	}

	return 0;
}

/*
 * This functions send presence packets during
 * windows_bcast time and go to standy by mode during
 * (interval_bcast - windows_bcast) time
 */
static void presence_connect(int spi_fd)
{
	struct nrf24_io_pack p;
	struct nrf24_ll_mgmt_pdu *opdu = (void *)p.payload;
	struct nrf24_ll_presence *llp =
				(struct nrf24_ll_presence *) opdu->payload;
	size_t len, nameLen;
	static unsigned long start;
	/* Start timeout */
	static uint8_t state = PRESENCE;

	switch (state) {
	case PRESENCE:
		/* Send Presence */
		if (mac_local.address.uint64 == 0)
			break;

		p.pipe = 0;
		opdu->type = NRF24_PDU_TYPE_PRESENCE;
		/* Send the mac address and thing name */
		llp->mac.address.uint64 = mac_local.address.uint64;

		len = sizeof(*opdu) + sizeof(*llp);

		/*
		 * Checks if need to truncate the name
		 * If header length + MAC length + name length is
		 * greater than MGMT_SIZE, then only sends the remaining.
		 * If not, sends the total name length.
		 */
		nameLen = (len + sizeof(THING_NAME) > MGMT_SIZE ?
				MGMT_SIZE - len : sizeof(THING_NAME));

		memcpy(llp->name, THING_NAME, nameLen);
		/* Increments name length */
		len += nameLen;

		phy_write(spi_fd, &p, len);
		/* Init time */
		start = hal_time_ms();
		state = TIMEOUT_WINDOW;
		break;
	case TIMEOUT_WINDOW:
		if (hal_timeout(hal_time_ms(), start, window_bcast) > 0)
			state = STANDBY;

		break;
	case STANDBY:
		phy_ioctl(spi_fd, NRF24_CMD_SET_STANDBY, NULL);
		state = TIMEOUT_INTERVAL;
		break;
	case TIMEOUT_INTERVAL:
		if (hal_timeout(hal_time_ms(), start, interval_bcast) > 0)
			state = PRESENCE;

		break;
	}
}

static void running(void)
{
	struct mgmt_nrf24_header *mgmtev_hdr;
	struct mgmt_evt_nrf24_disconnected *mgmtev_dc;
	static int state = START_MGMT;
	/* Index peers */
	static int sockIndex = 1;
	static unsigned long start;

	switch (state) {
	case START_MGMT:
		/* Set channel to management channel */
		phy_ioctl(driverIndex, NRF24_CMD_SET_CHANNEL, &channel_mgmt);
		/* Start timeout */
		start = hal_time_ms();
		/* Go to next state */
		state = MGMT;
	case MGMT:

		read_mgmt(driverIndex);
		write_mgmt(driverIndex);

		/* Broadcasting/acceptor */
		if (listen)
			presence_connect(driverIndex);

		/* Peers connected? */
		if (pipe_bitmask & PIPE_RAW_BITMASK) {
			if (hal_timeout(hal_time_ms(), start, MGMT_TIMEOUT) > 0)
				state = START_RAW;
		}
		break;

	case START_RAW:
		/* Set channel to data channel */
		phy_ioctl(driverIndex, NRF24_CMD_SET_CHANNEL, &channel_raw);
		/* Start timeout */
		start = hal_time_ms();

		/* Go to next state */
		state = RAW;
	case RAW:

		/* Start broadcast or scan? */
		if (CHK_BIT(pipe_bitmask, 0)) {
			/* Check if 60ms timeout occurred */
			if (hal_timeout(hal_time_ms(), start, RAW_TIMEOUT) > 0)
				state = START_MGMT;
		}

		/* Check if pipe is allocated */
		if (peers[sockIndex-1].pipe != -1) {
			read_raw(driverIndex, sockIndex);
			write_raw(driverIndex, sockIndex);

			/*
			 * If keepalive is enabled
			 * Check if timeout occurred and generates
			 * disconnect event
			 */

			if (check_keepalive(driverIndex, sockIndex) == -ETIMEDOUT &&
				mgmt.len_rx == 0) {

				mgmtev_hdr = (struct mgmt_nrf24_header *)
								mgmt.buffer_rx;
				mgmtev_dc = (struct mgmt_evt_nrf24_disconnected *)
							mgmtev_hdr->payload;

				mgmtev_hdr->opcode = MGMT_EVT_NRF24_DISCONNECTED;

				mgmtev_dc->mac.address.uint64 =
					peers[sockIndex-1].mac.address.uint64;
				mgmt.len_rx = sizeof(*mgmtev_hdr) +
								sizeof(*mgmtev_dc);

				/* TODO: Send disconnect packet to slave */

				/* Free pipe */
				CLR_BIT(pipe_bitmask, peers[sockIndex - 1].pipe);
				peers[sockIndex - 1].pipe = -1;
				peers[sockIndex - 1].keepalive = 0;
				phy_ioctl(driverIndex, NRF24_CMD_RESET_PIPE,
								&sockIndex);
			}
		}

		sockIndex++;
		/* Resets sockIndex if sockIndex > CONNECTION_COUNTER */
		if (sockIndex > CONNECTION_COUNTER)
			sockIndex = 1;

		break;

	}
}

/* Global functions */
int hal_comm_init(const char *pathname, const struct nrf24_mac *mac)
{
	/* If driver not opened */
	if (driverIndex != -1)
		return -EPERM;

	/* Open driver and returns the driver index */
	driverIndex = phy_open(pathname);
	if (driverIndex < 0)
		return driverIndex;

	mac_local.address.uint64 = mac->address.uint64;

	return 0;
}

int hal_comm_deinit(void)
{
	int err;
	uint8_t i;

	/* If try to close driver with no driver open */
	if (driverIndex == -1)
		return -EPERM;

	/* Clear all peers*/
	for (i = 0; i < CONNECTION_COUNTER; i++) {
		if (peers[i].pipe != -1)
			peers[i].pipe = -1;
	}

	pipe_bitmask = 0b00000001;
	/* Close driver */
	err = phy_close(driverIndex);
	if (err < 0)
		return err;

	/* Dereferencing driverIndex */
	driverIndex = -1;

	return err;
}

int hal_comm_socket(int domain, int protocol)
{
	int retval;
	struct addr_pipe ap;

	/* If domain is not NRF24 */
	if (domain != HAL_COMM_PF_NRF24)
		return -EPERM;

	/* If not initialized */
	if (driverIndex == -1)
		return -EPERM;	/* Operation not permitted */

	switch (protocol) {

	case HAL_COMM_PROTO_MGMT:
		/* If Management, disable ACK and returns 0 */
		if (mgmt.pipe == 0)
			return -EUSERS; /* Returns too many users */
		ap.ack = false;
		retval = 0;
		mgmt.pipe = 0;

		/* Copy broadcast address */
		memcpy(ap.aa, aa_pipe0, sizeof(ap.aa));
		break;

	case HAL_COMM_PROTO_RAW:
		if (mgmt.pipe == -1) {
			/* If Management is not open*/
			ap.ack = false;
			mgmt.pipe = 0;
			retval = 0;
			/* Copy broadcast address */
			memcpy(ap.aa, aa_pipe0, sizeof(ap.aa));
			break;
		}
		/*
		 * If raw data, enable ACK
		 * and returns an available pipe
		 * from 1 to 5
		 */
		retval = alloc_pipe();
		/* If not pipe available */
		if (retval < 0)
			return -EUSERS; /* Returns too many users */

		ap.ack = true;

		/*
		 * Copy the 5 LSBs of master mac addres
		 * to access address and the last least
		 * significant byte is the pipe index.
		 */
		memcpy(ap.aa, &mac_local.address.b[3], sizeof(ap.aa));
		ap.aa[0] = (uint8_t)retval;

		break;

	default:
		return -EINVAL; /* Invalid argument */
	}

	ap.pipe = retval;

	/* Open pipe */
	phy_ioctl(driverIndex, NRF24_CMD_SET_PIPE, &ap);

	return retval;
}

int hal_comm_close(int sockfd)
{
	if (driverIndex == -1)
		return -EPERM;

	/* Pipe 0 is not closed because ACK arrives in this pipe */
	if (sockfd >= 1 && sockfd <= 5 && peers[sockfd-1].pipe != -1) {
		/* Send disconnect packet */
		if (mac_local.address.uint64 != 0)
			/* Slave side */
			write_disconnect(driverIndex, sockfd,
					peers[sockfd-1].mac, mac_local);
		/* Free pipe */
		peers[sockfd-1].pipe = -1;
		CLR_BIT(pipe_bitmask, peers[sockfd - 1].pipe);
		phy_ioctl(driverIndex, NRF24_CMD_RESET_PIPE, &sockfd);
		/* Disable to send keep alive request */
		peers[sockfd-1].keepalive = 0;
	}

	return 0;
}

ssize_t hal_comm_read(int sockfd, void *buffer, size_t count)
{
	size_t length = 0;

	/* Run background procedures */
	running();

	if (sockfd < 0 || sockfd > 5 || count == 0)
		return -EINVAL;

	/* If management */
	if (sockfd == 0) {
		/* If has something to read */
		if (mgmt.len_rx != 0) {
			/*
			 * If the amount of bytes available
			 * to be read is greather than count
			 * then read count bytes
			 */
			length = mgmt.len_rx > count ? count : mgmt.len_rx;
			/* Copy rx buffer */
			memcpy(buffer, mgmt.buffer_rx, length);

			/* Reset rx len */
			mgmt.len_rx = 0;
		} else /* Return -EAGAIN has nothing to be read */
			return -EAGAIN;

	} else if (peers[sockfd-1].len_rx != 0) {
		/*
		 * If the amount of bytes available
		 * to be read is greather than count
		 * then read count bytes
		 */
		length = peers[sockfd-1].len_rx > count ?
				 count : peers[sockfd-1].len_rx;
		/* Copy rx buffer */
		memcpy(buffer, peers[sockfd-1].buffer_rx, length);
		/* Reset rx len */
		peers[sockfd-1].len_rx = 0;
	} else
		return -EAGAIN;

	/* Returns the amount of bytes read */
	return length;
}


ssize_t hal_comm_write(int sockfd, const void *buffer, size_t count)
{

	/* Run background procedures */
	running();

	if (sockfd < 1 || sockfd > 5 || count == 0 || count > DATA_SIZE)
		return -EINVAL;

	/* If already has something to write then returns busy */
	if (peers[sockfd-1].len_tx != 0)
		return -EBUSY;

	/* Copy data to be write in tx buffer */
	memcpy(peers[sockfd-1].buffer_tx, buffer, count);
	peers[sockfd-1].len_tx = count;

	return count;
}

int hal_comm_listen(int sockfd)
{
	/* Init listen */
	listen = 1;

	/* pipe0 used for broadcasting/scanning */
	SET_BIT(pipe_bitmask, 0);

	return 0;
}

int hal_comm_accept(int sockfd, uint64_t *addr)
{

	/* TODO: Run background procedures */
	struct mgmt_nrf24_header *mgmtev_hdr =
				(struct mgmt_nrf24_header *) mgmt.buffer_rx;
	struct mgmt_evt_nrf24_connected *mgmtev_cn =
			(struct mgmt_evt_nrf24_connected *)mgmtev_hdr->payload;
	struct addr_pipe p_addr;
	int pipe;
	/* Run background procedures */
	running();

	if (mgmt.len_rx == 0)
		return -EAGAIN;

	/* Free management read to receive new packet */
	mgmt.len_rx = 0;

	if (mgmtev_hdr->opcode != MGMT_EVT_NRF24_CONNECTED ||
		mgmtev_cn->dst.address.uint64 != mac_local.address.uint64)
		return -EAGAIN;

	pipe = alloc_pipe();
	/* If not pipe available */
	if (pipe < 0)
		return -EUSERS; /* Returns too many users */

	/* If accept then stop listen */
	listen = 0;

	/* Set aa in pipe */
	p_addr.pipe = pipe;
	memcpy(p_addr.aa, mgmtev_cn->aa, sizeof(p_addr.aa));
	p_addr.ack = 1;
	/*open pipe*/
	phy_ioctl(driverIndex, NRF24_CMD_SET_PIPE, &p_addr);

	/* Source address for keepalive message */
	peers[pipe-1].mac.address.uint64 =
		mgmtev_cn->src.address.uint64;
	/* Disable keep alive request */
	peers[pipe-1].keepalive = 0;
	/* Start timeout */
	peers[pipe-1].keepalive_anchor = hal_time_ms();

	/* Copy peer address */
	*addr = mgmtev_cn->src.address.uint64;

	/* Return pipe */
	return pipe;
}


int hal_comm_connect(int sockfd, uint64_t *addr)
{

	struct nrf24_ll_mgmt_pdu *opdu =
		(struct nrf24_ll_mgmt_pdu *)mgmt.buffer_tx;
	struct nrf24_ll_mgmt_connect *payload =
				(struct nrf24_ll_mgmt_connect *) opdu->payload;
	size_t len;

	/* Run background procedures */
	running();

	/* If already has something to write then returns busy */
	if (mgmt.len_tx != 0)
		return -EBUSY;

	opdu->type = NRF24_PDU_TYPE_CONNECT_REQ;

	payload->src_addr = mac_local;
	payload->dst_addr.address.uint64 = *addr;
	payload->channel = channel_raw;
	/*
	 * Set in payload the addr to be set in client.
	 * sockfd contains the pipe allocated for the client
	 * aa_pipes contains the Access Address for each pipe
	 */

	/*
	 * Copy the 5 LSBs of master mac addres
	 * to access address and the last least
	 * significant byte is the socket index.
	 */

	memcpy(payload->aa, &mac_local.address.b[3],
		sizeof(payload->aa));
	payload->aa[0] = (uint8_t)sockfd;

	/* Source address for keepalive message */
	peers[sockfd-1].mac.address.uint64 = *addr;

	len = sizeof(struct nrf24_ll_mgmt_connect);
	len += sizeof(struct nrf24_ll_mgmt_pdu);

	/* Start timeout */
	peers[sockfd-1].keepalive_anchor = hal_time_ms();
	/* Enable keep alive: 5 attempts until timeout */
	peers[sockfd-1].keepalive = 1;
	mgmt.len_tx = len;

	return 0;
}

int nrf24_str2mac(const char *str, struct nrf24_mac *mac)
{
	/* Parse the input string into 8 bytes */
	int rc = sscanf(str,
		"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		&mac->address.b[0], &mac->address.b[1], &mac->address.b[2],
		&mac->address.b[3], &mac->address.b[4], &mac->address.b[5],
		&mac->address.b[6], &mac->address.b[7]);

	return (rc != 8 ? -1 : 0);
}

int nrf24_mac2str(const struct nrf24_mac *mac, char *str)
{
	/* Write nrf24_mac.address into string buffer in hexadecimal format */
	int rc = sprintf(str,
		"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			mac->address.b[0], mac->address.b[1], mac->address.b[2],
			mac->address.b[3], mac->address.b[4], mac->address.b[5],
			mac->address.b[6], mac->address.b[7]);

	return (rc != 23 ? -1 : 0);
}
