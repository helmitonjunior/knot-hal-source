/*
 * Copyright (c) 2016, CESAR.
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license. See the LICENSE file for details.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "spi.h"
#include "nrf24l01.h"
#include "nrf24l01_io.h"
 #include "crypto.h"

/* Pipes addresses base */
#define PIPE0_ADDR_BASE 0x55aa55aa5aLL
#define PIPE1_ADDR_BASE 0xaa55aa55a5LL

  /*Local and Stranger Keys for Enc/Decription*/
//local key pair
uint8_t private_4[NUM_ECC_DIGITS] = {0xA3, 0xB0, 0x24, 0xBB, 0xA9, 0xA2, 0xC2, 0xC0, 0xB2, 0xE6, 0xEB, 0x32, 0xF7, 0x40, 0xF3, 0xD7, 0xB6, 0xFA, 0x27, 0x2F, 0xA8, 0x09, 0xE7, 0x6D, 0xF7, 0x7F, 0xF8, 0xB5, 0x7F, 0x0D, 0xDF, 0xBE};
uint8_t public_4x[NUM_ECC_DIGITS] = {0x03, 0x7A, 0xDC, 0x3D, 0x4C, 0x9D, 0xDD, 0x77, 0xA8, 0xC2, 0x65, 0x5C, 0xA0, 0xE8, 0xCC, 0x51, 0xA7, 0x21, 0x6B, 0xD1, 0x9A, 0x4A, 0xA3, 0x55, 0x71, 0xAC, 0x2A, 0x72, 0xFE, 0x9C, 0xE6, 0x06};
uint8_t public_4y[NUM_ECC_DIGITS] = {0x96, 0x3F, 0x32, 0x1B, 0x42, 0x1D, 0xE1, 0x47, 0x3D, 0xA5, 0xE8, 0x57, 0xDF, 0xBA, 0x09, 0xF2, 0xB0, 0x2E, 0xEF, 0x79, 0xD0, 0x31, 0xF1, 0xCD, 0xDB, 0x17, 0x70, 0x08, 0xC3, 0x37, 0x7E, 0x84};
// public stranger key
uint8_t public_3x[NUM_ECC_DIGITS] = {0x8C, 0xDC, 0xCF, 0xD4, 0xCD, 0x34, 0x3F, 0x9B, 0x0D, 0x70, 0x57, 0x3D, 0x40, 0x1A, 0x6F, 0xFE, 0xB0, 0x9C, 0x05, 0x47, 0xE4, 0x02, 0x8C, 0xAF, 0x0C, 0x2D, 0xDB, 0x8A, 0xC9, 0x66, 0x37, 0x1F};
uint8_t public_3y[NUM_ECC_DIGITS] = {0xF4, 0x60, 0xB9, 0x86, 0x5A, 0xC5, 0xB0, 0x41, 0xF9, 0x53, 0x18, 0xCF, 0x9A, 0x7B, 0x24, 0xF8, 0x75, 0x94, 0xD9, 0xEF, 0x49, 0xC1, 0x9A, 0xAE, 0xE4, 0xE5, 0x64, 0xAD, 0x58, 0x48, 0x6D, 0x36};
//uint8_t private_3[NUM_ECC_DIGITS] = { 0x8C, 0xDC, 0xCF, 0xD4, 0xCD, 0x34, 0x3F, 0x9B, 0x0D, 0x70, 0x57, 0x3D, 0x40, 0x1A, 0x6F, 0xFE, 0xB0, 0x9C, 0x05, 0x47, 0xE4, 0x02, 0x8C, 0xAF, 0x0C, 0x2D, 0xDB, 0x8A, 0xC9, 0x66, 0x37, 0x1F};
//secret
uint8_t skey[32];
//stores de ciphered data. Must be bigger than plaintext, size depends on algorithm
uint8_t buffer[48];

typedef struct {
	uint8_t enaa,
	en_rxaddr,
	rx_addr,
	rx_pw;
} pipe_reg_t;

static const pipe_reg_t pipe_reg[] = {
	{ NRF24_AA_P0, NRF24_EN_RXADDR_P0, NRF24_RX_ADDR_P0, NRF24_RX_PW_P0 },
	{ NRF24_AA_P1, NRF24_EN_RXADDR_P1, NRF24_RX_ADDR_P1, NRF24_RX_PW_P1 },
	{ NRF24_AA_P2, NRF24_EN_RXADDR_P2, NRF24_RX_ADDR_P2, NRF24_RX_PW_P2 },
	{ NRF24_AA_P3, NRF24_EN_RXADDR_P3, NRF24_RX_ADDR_P3, NRF24_RX_PW_P3 },
	{ NRF24_AA_P4, NRF24_EN_RXADDR_P4, NRF24_RX_ADDR_P4, NRF24_RX_PW_P4 },
	{ NRF24_AA_P5, NRF24_EN_RXADDR_P5, NRF24_RX_ADDR_P5, NRF24_RX_PW_P5 }
};

typedef enum {
	UNKNOWN_MODE,
	POWER_DOWN_MODE,
	STANDBY_I_MODE,
	RX_MODE,
	TX_MODE,
	STANDBY_II_MODE,
} en_modes_t;

static en_modes_t m_mode = UNKNOWN_MODE;

static uint8_t m_pipe0_addr = NRF24_PIPE0_ADDR;

#define DATA_SIZE	sizeof(uint8_t)

/* Time delay in microseconds (us) */
#define TPD2STBY	5000
#define TSTBY2A		130

/* Send to spi transfer the read command
* return the value that was read in reg
*/
static inline int8_t inr(uint8_t reg)
{
	uint8_t value = NRF24_NOP;

	reg = NRF24_R_REGISTER(reg);
	spi_transfer(&reg, DATA_SIZE, &value, DATA_SIZE);
	return (int8_t)value;
}

static inline void inr_data(uint8_t reg, void *pd, uint16_t len)
{
	memset(pd, NRF24_NOP, len);
	reg = NRF24_R_REGISTER(reg);
	spi_transfer(&reg, DATA_SIZE, pd, len);
}

/* Send to spi transfer the write command
 * and the data that will be written
 */
static inline void outr(uint8_t reg, uint8_t value)
{
	reg = NRF24_W_REGISTER(reg);
	spi_transfer(&reg, DATA_SIZE, &value, DATA_SIZE);
}

static inline void outr_data(uint8_t reg, void *pd, uint16_t len)
{
	reg = NRF24_W_REGISTER(reg);
	spi_transfer(&reg, DATA_SIZE, pd, len);
}

/* Send to spi transfer the write command
* the commands are in pages 53-58 from datasheet
*/
static inline int8_t command(uint8_t cmd)
{
	spi_transfer(NULL, 0, &cmd, DATA_SIZE);
	/* Return device status register */
	return (int8_t)cmd;
}

static inline int8_t command_data(uint8_t cmd, void *pd, uint16_t len)
{
	spi_transfer(&cmd, DATA_SIZE, pd, len);
	/* Return device status register */
	return command(NRF24_NOP);
}

static void set_address_pipe(uint8_t reg, uint8_t pipe_addr)
{
	uint16_t len;
	uint64_t  addr = (pipe_addr == NRF24_PIPE0_ADDR) ?
					PIPE0_ADDR_BASE : PIPE1_ADDR_BASE;

	switch (reg) {
	case NRF24_TX_ADDR:
	case NRF24_RX_ADDR_P0:
	case NRF24_RX_ADDR_P1:
		len = NRF24_AW_RD(inr(NRF24_SETUP_AW));
		break;
	default:
		len = DATA_SIZE;
	}

	addr += (pipe_addr << 4) + pipe_addr;
	outr_data(reg, &addr, len);
}

static int8_t set_standby1(void)
{
	disable();
	return 0;
}

int8_t nrf24l01_set_standby(void)
{
	set_standby1();
	return command(NRF24_NOP);
}

/*
* nrf24l01_init:
* Init spi
* Configure the radio to data rate of 1Mbps
*/
int8_t nrf24l01_init(const char *dev)
{
	uint8_t	value;
	int8_t err;

	/* example of dev = "/dev/spidev0.0" */
	err = io_setup(dev);
	if (err < 0)
		return err;

	/* Reset device in power down mode */
	outr(NRF24_CONFIG, NRF24_CONFIG_RST);
	/* Delay to establish to operational timing of the nRF24L01 */
	delay_us(TPD2STBY);

	/* Reset channel and TX observe registers */
	outr(NRF24_RF_CH, inr(NRF24_RF_CH) & ~NRF24_RF_CH_MASK);
	/* Set the device channel */
	outr(NRF24_RF_CH, NRF24_CH(NRF24_CHANNEL_DEFAULT));

	/* Set RF speed and output power */
	value = inr(NRF24_RF_SETUP) & ~NRF24_RF_SETUP_MASK;
	outr(NRF24_RF_SETUP, value | NRF24_RF_DR(NRF24_DATA_RATE)|
			NRF24_RF_PWR(NRF24_POWER));

	/* Set address widths */
	value = inr(NRF24_SETUP_AW) & ~NRF24_SETUP_AW_MASK;
	outr(NRF24_SETUP_AW, value | NRF24_AW(NRF24_ADDR_WIDTHS));

	/* Set device to standby-I mode */
	value = inr(NRF24_CONFIG) & ~NRF24_CONFIG_MASK;
	value |= NRF24_CFG_MASK_RX_DR | NRF24_CFG_MASK_TX_DS;
	value |= NRF24_CFG_MASK_MAX_RT | NRF24_CFG_EN_CRC;
	value |= NRF24_CFG_CRCO | NRF24_CFG_PWR_UP;
	outr(NRF24_CONFIG, value);

	delay_us(TPD2STBY);

	/* Disable Auto Retransmit Count */
	outr(NRF24_SETUP_RETR, NRF24_RETR_ARC(NRF24_ARC_DISABLE));

	/* Disable all Auto Acknowledgment of pipes */
	outr(NRF24_EN_AA, inr(NRF24_EN_AA) & ~NRF24_EN_AA_MASK);

	/* Disable all RX addresses */
	outr(NRF24_EN_RXADDR, inr(NRF24_EN_RXADDR)
		& ~NRF24_EN_RXADDR_MASK);

	/*
	 * Features available:
	 * EN_DPL Enable dynamic payload to all pipes -> Enable
	 * EN_ACK_PAY: Enables Payload with ACK -> Disable
	 * EN_DYN_ACK: Enables the W_TX_PAYLOAD_NOACK command -> Disable
	 */

	/*
	 * A problem occurred when nrf2l01+PA+LNA communicates
	 * with nrf2l01+ (without antenna), the ack packages was lost.
	 * The feature EN_DYN_ACK was disable and the communicates now work.
	 * As EN_DYN_ACK isn't enable all the pipe will work with
	 * ack by default.
	 * The option no ack can be set in function nrf24l01_set_ptx.
	 */
	outr(NRF24_FEATURE, (inr(NRF24_FEATURE) & ~NRF24_FEATURE_MASK)
		| NRF24_FT_EN_DPL);

	value = inr(NRF24_DYNPD) & ~NRF24_DYNPD_MASK;
	value |= NRF24_DPL_P5 | NRF24_DPL_P4;
	value |= NRF24_DPL_P3 | NRF24_DPL_P2;
	value |= NRF24_DPL_P1 | NRF24_DPL_P0;

	outr(NRF24_DYNPD, value);

	/* Reset pending status */
	value = inr(NRF24_STATUS) & ~NRF24_STATUS_MASK;
	outr(NRF24_STATUS, value | NRF24_ST_RX_DR
		| NRF24_ST_TX_DS | NRF24_ST_MAX_RT);


	/* Reset all the FIFOs */
	command(NRF24_FLUSH_TX);
	command(NRF24_FLUSH_RX);

	m_pipe0_addr = NRF24_PIPE0_ADDR;

	return 0;
}

/*
* nrf24l01_set_channel:
* Bandwidth < 1MHz at 250kbps
* Bandwidth < 1MHZ at 1Mbps
* Bandwidth < 2MHz at 2Mbps
* 2Mbps -> channel max is 54
* 1Mbps -> channel max is 116
*/
int8_t nrf24l01_set_channel(uint8_t ch)
{
	uint8_t max;

	max = NRF24_RF_DR(inr(NRF24_RF_SETUP)) == NRF24_DR_2MBPS ?
			NRF24_CH_MAX_2MBPS : NRF24_CH_MAX_1MBPS;

	if (ch != _CONSTRAIN(ch, NRF24_CH_MIN, max))
		return -1;

	if (ch != NRF24_CH(inr(NRF24_RF_CH))) {
		set_standby1();
		outr(NRF24_STATUS, NRF24_ST_RX_DR
			| NRF24_ST_TX_DS | NRF24_ST_MAX_RT);
		command(NRF24_FLUSH_TX);
		command(NRF24_FLUSH_RX);
		/* Set the device channel */
		outr(NRF24_RF_CH,
			NRF24_CH(_CONSTRAIN(ch, NRF24_CH_MIN, max)));
	}
	return 0;
}

/*
* nrf24l01_open_pipe:
* 0 <= pipe <= 5
* Pipes are enabled with the bits in the EN_RXADDR
*/
int8_t nrf24l01_open_pipe(uint8_t pipe, uint8_t pipe_addr)
{
	pipe_reg_t rpipe;

	if (pipe > NRF24_PIPE_MAX || pipe_addr > NRF24_PIPE_ADDR_MAX)
		return -1;

	memcpy(&rpipe, &pipe_reg[pipe], sizeof(pipe_reg_t));

	/* Enable pipe */
	if (!(inr(NRF24_EN_RXADDR) & rpipe.en_rxaddr)) {
		if (rpipe.rx_addr == NRF24_RX_ADDR_P0)
			m_pipe0_addr = pipe_addr;

		set_address_pipe(rpipe.rx_addr, pipe_addr);
		outr(NRF24_EN_RXADDR, inr(NRF24_EN_RXADDR)
			| rpipe.en_rxaddr);

		outr(NRF24_EN_AA, inr(NRF24_EN_AA) | rpipe.enaa);
	}
	return 0;
}

/* nrf24l01_set_ptx:
* set pipe to send data;
* the radio will be the Primary Transmitter (PTX).
* See page 31 of nRF24L01_Product_Specification_v2_0.pdf
*/
int8_t nrf24l01_set_ptx(uint8_t pipe_addr, bool ack)
{
	/* put the radio in mode standby-1 */
	set_standby1();
	/* TX Settling */

	/*
	 * If the ack option is disable is necessary disable auto-ack in pipe 0
	 * because ack always arrive in pipe 0
	 * and the ack is enable for all pipe by default
	 * as configured in init
	 */
	if (!ack)
		outr(NRF24_EN_AA, inr(NRF24_EN_AA) & ~pipe_reg[0].enaa);
	else
		outr(NRF24_EN_AA, inr(NRF24_EN_AA) | pipe_reg[0].enaa);

	set_address_pipe(NRF24_RX_ADDR_P0, pipe_addr);
	set_address_pipe(NRF24_TX_ADDR, pipe_addr);
	#if (NRF24_ARC != NRF24_ARC_DISABLE)
		/*
		* Set ARC and ARD by pipe index to different
		* retry periods to reduce data collisions
		* compute ARD range: 1500us <= ARD[pipe] <= 4000us
		*/
		outr(NRF24_SETUP_RETR,
			NRF24_RETR_ARD(((pipe_addr * 2) + 5))
			| NRF24_RETR_ARC(NRF24_ARC));
	#endif
	outr(NRF24_STATUS, NRF24_ST_TX_DS | NRF24_ST_MAX_RT);
	outr(NRF24_CONFIG, inr(NRF24_CONFIG) & ~NRF24_CFG_PRIM_RX);
	/* Enable and delay time to TSTBY2A timing */
	enable();
	delay_us(TSTBY2A);
	return 0;
}

/* nrf24l01_ptx_data:
* TX mode Transmit Packet
* See NRF24L01 datasheet table 20. 'ack' parameter selects
* the SPI NRF24 command to be sent.
*/
int8_t nrf24l01_ptx_data(void *pdata, uint16_t len)
{

	if (pdata == NULL || len == 0 || len > NRF24_PAYLOAD_SIZE)
		return -1;

	/*Encrypt Data Here*/
            deriveSecret (public_3x, public_3y, private_4, public_4x, public_4y, skey);
            int ciphertext_len = encrypt (pdata, len, skey, 0, buffer);
            memcpy(pdata, buffer, 32);

	/*
	 * Returns the current operating status
	 * of NRF24L01 after entering data in TX FIFO
	 * 1: TX FIFO full or 0: Available locations in TX FIFO.
	 */
	return ST_TX_STATUS(command_data(NRF24_W_TX_PAYLOAD,
			pdata, len));
}

/*nrf24l01_ptx_wait_datasent:
* wait while data is being sent
* check Data Sent TX FIFO interrupt
*/
int8_t nrf24l01_ptx_wait_datasent(void)
{
	uint16_t value;

	while (!((value = inr(NRF24_STATUS)) & NRF24_ST_TX_DS)) {
		/* if arrived in Maximum number of TX retransmits
		 * the send failed
		 */
		if (value & NRF24_ST_MAX_RT) {
			outr(NRF24_STATUS, NRF24_ST_MAX_RT);
			command(NRF24_FLUSH_TX);
			return -1;
		}
	}
	return 0;
}

/* nrf24l01_set_prx:
* set pipe to send data;
* the radio will be the Primary Receiver (PRX).
* See page 33 of nRF24L01_Product_Specification_v2_0.pdf
*/
int8_t nrf24l01_set_prx(void)
{
	set_standby1();
	set_address_pipe(NRF24_RX_ADDR_P0, m_pipe0_addr);
	/* RX Settings */
	outr(NRF24_STATUS, NRF24_ST_RX_DR);
	outr(NRF24_CONFIG, inr(NRF24_CONFIG) | NRF24_CFG_PRIM_RX);
	/* Enable and delay time to TSTBY2A timing */
	enable();
	delay_us(TSTBY2A);

	return 0;
}

/*
* nrf24l01_prx_pipe_available:
* Return the pipe where the first data of the RX FIFO are.
*/
int8_t nrf24l01_prx_pipe_available(void)
{
	uint8_t pipe = NRF24_NO_PIPE;

	if (!(inr(NRF24_FIFO_STATUS) & NRF24_FIFO_RX_EMPTY)) {
		pipe = NRF24_ST_RX_P_NO(inr(NRF24_STATUS));
		if (pipe > NRF24_PIPE_MAX)
			pipe = NRF24_NO_PIPE;
	}
	return (int8_t)pipe;
}

/*nrf24l01_prx_data:
* return the len of data received
* Send command to read data width for the RX FIFO
*/
int8_t nrf24l01_prx_data(void *pdata, uint16_t len)
{
	uint16_t		rxlen = 0;

	outr(NRF24_STATUS, NRF24_ST_RX_DR);

	command_data(NRF24_R_RX_PL_WID, &rxlen, DATA_SIZE);
	/* Note: flush RX FIFO if the value read is larger than 32 bytes.*/
	if (rxlen > NRF24_PAYLOAD_SIZE) {
		command(NRF24_FLUSH_RX);
		return 0;
	}

	if (rxlen != 0) {
		rxlen = _MIN(len, rxlen);
		command_data(NRF24_R_RX_PAYLOAD, pdata, rxlen);
	}

	/*Decrypt Data Here*/
	deriveSecret (public_3x, public_3y, private_4, public_4x, public_4y, skey);
	int decryptedtext_len = decrypt(pdata, len+1, skey, 0, buffer);
	memcpy(pdata, buffer, 32);

	return (int8_t)rxlen;
}
