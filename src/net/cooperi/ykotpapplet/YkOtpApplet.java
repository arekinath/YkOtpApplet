/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.ykotpapplet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.framework.APDUException;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacard.security.SecretKey;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;
import javacardx.apdu.ExtendedLength;

public class YkOtpApplet extends Applet implements ExtendedLength
{
	private static final byte[] APP_VERSION = {
		(byte)0x04, (byte)0x00, (byte)0x00
	};

	private static final byte INS_API_REQ = (byte)0x01;
	private static final byte INS_OTP = (byte)0x02;
	private static final byte INS_STATUS = (byte)0x03;
	private static final byte INS_NDEF = (byte)0x04;

	private static final byte CMD_SET_CONF_1 = (byte)0x01;
	private static final byte CMD_SET_CONF_2 = (byte)0x03;
	private static final byte CMD_UPDATE_CONF_1 = (byte)0x04;
	private static final byte CMD_UPDATE_CONF_2 = (byte)0x05;
	private static final byte CMD_SWAP = (byte)0x06;
	private static final byte CMD_GET_SERIAL = (byte)0x10;
	private static final byte CMD_DEV_CONF = (byte)0x11;
	private static final byte CMD_SET_SCAN_MAP = (byte)0x12;
	private static final byte CMD_GET_YK4_CAPS = (byte)0x13;

	private static final byte CMD_OTP_1 = (byte)0x20;
	private static final byte CMD_OTP_2 = (byte)0x28;

	private static final byte CMD_HMAC_1 = (byte)0x30;
	private static final byte CMD_HMAC_2 = (byte)0x38;

	private static final byte PGM_SEQ_INVALID = (byte)0x00;
	private static final short CONFIG1_VALID = (short)0x01;
	private static final short CONFIG2_VALID = (short)0x02;
	private static final short CONFIG1_TOUCH = (short)0x04;
	private static final short CONFIG2_TOUCH = (short)0x08;

	private byte pgmSeq = PGM_SEQ_INVALID;
	private byte[] serial = null;

	private SlotConfig[] slots;

	private byte[] hmacBuf = null;

	private RandomData randData = null;
	private MessageDigest sha1 = null;

	public static void
	install(byte[] info, short off, byte len)
	{
		final YkOtpApplet applet = new YkOtpApplet();
		applet.register();
	}

	protected
	YkOtpApplet()
	{
		randData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

		serial = new byte[4];
		serial[0] = (byte)0x10;
		randData.generateData(serial, (short)1, (short)3);

		slots = new SlotConfig[2];
		slots[0] = new SlotConfig();
		slots[1] = new SlotConfig();

		hmacBuf = JCSystem.makeTransientByteArray((short)128,
		    JCSystem.CLEAR_ON_RESET);

		sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
	}

	public void
	process(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		final byte ins = buffer[ISO7816.OFFSET_INS];

		if (!apdu.isISOInterindustryCLA()) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			return;
		}

		if (selectingApplet()) {
			handleAppSelect(apdu);
			return;
		}

		switch (ins) {
		case INS_STATUS:
			handleStatus(apdu);
			break;
		case INS_API_REQ:
			handleApiRequest(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void
	handleAppSelect(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short len, le;
		le = apdu.setOutgoing();
		len = 0;

		buffer[len++] = APP_VERSION[0];
		buffer[len++] = APP_VERSION[1];
		buffer[len++] = APP_VERSION[2];
		buffer[len++] = pgmSeq;

		short touchLevel = 0;
		if (slots[0].programmed)
			touchLevel |= CONFIG1_VALID;
		if (slots[1].programmed)
			touchLevel |= CONFIG2_VALID;
		/* touchLevel is little-endian */
		buffer[len++] = (byte)(touchLevel & (short)0x00ff);
		buffer[len++] = (byte)((touchLevel & (short)0xff00) >> 8);

		buffer[len++] = 0x02;
		buffer[len++] = 0x0F;
		buffer[len++] = 0x00;
		buffer[len++] = 0x00;

		len = le > 0 ? (le > len ? len : le) : len;
		apdu.setOutgoingLength(len);
		apdu.sendBytes((short)0, len);
	}

	private void
	handleStatus(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short len, le;
		le = apdu.setOutgoing();
		len = 0;

		buffer[len++] = APP_VERSION[0];
		buffer[len++] = APP_VERSION[1];
		buffer[len++] = APP_VERSION[2];
		buffer[len++] = pgmSeq;

		short touchLevel = 0;
		if (slots[0].programmed)
			touchLevel |= CONFIG1_VALID;
		if (slots[1].programmed)
			touchLevel |= CONFIG2_VALID;
		/* touchLevel is little-endian */
		buffer[len++] = (byte)(touchLevel & (short)0x00ff);
		buffer[len++] = (byte)((touchLevel & (short)0xff00) >> 8);

		len = le > 0 ? (le > len ? len : le) : len;
		apdu.setOutgoingLength(len);
		apdu.sendBytes((short)0, len);
	}

	private void
	handleApiRequest(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		final byte cmd = buffer[ISO7816.OFFSET_P1];

		switch (cmd) {
		case CMD_GET_SERIAL:
			handleGetSerial(apdu);
			break;
		case CMD_SET_CONF_1:
			programSlot(apdu, slots[0]);
			break;
		case CMD_SET_CONF_2:
			programSlot(apdu, slots[1]);
			break;
		case CMD_HMAC_1:
			if (!slots[0].programmed) {
				ISOException.throwIt(ISO7816.SW_NO_ERROR);
				return;
			}
			sendHmac(apdu, slots[0].key);
			break;
		case CMD_HMAC_2:
			if (!slots[1].programmed) {
				ISOException.throwIt(ISO7816.SW_NO_ERROR);
				return;
			}
			sendHmac(apdu, slots[1].key);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			return;
		}
	}

	private void
	programSlot(APDU apdu, SlotConfig slot)
	{
		final byte[] buffer = apdu.getBuffer();

		byte i;
		short lc, hn, le;

		lc = apdu.setIncomingAndReceive();
		if (lc != (short)(buffer[ISO7816.OFFSET_LC] & 0x00FF)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

		if (slot.read(buffer, apdu.getOffsetCdata(), lc)) {
			pgmSeq++;
		}

		handleStatus(apdu);
	}

	private void
	sendHmac(APDU apdu, byte[] key)
	{
		final byte[] buffer = apdu.getBuffer();

		if (buffer[ISO7816.OFFSET_LC] > (byte)64) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

		byte i;
		short lc, hn, le;

		lc = apdu.setIncomingAndReceive();
		if (lc != (short)(buffer[ISO7816.OFFSET_LC] & 0x00FF)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return;
		}

		for (i = (byte)0; i < (byte)64; ++i) {
			hmacBuf[i] = (byte)((byte)0x36 ^ key[i]);
		}
		Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(),
		    hmacBuf, (short)64, lc);

		sha1.reset();
		hn = sha1.doFinal(hmacBuf, (short)0, (short)(64 + lc),
		    hmacBuf, (short)64);

		for (i = (byte)0; i < (byte)64; ++i) {
			hmacBuf[i] = (byte)((byte)0x5C ^ key[i]);
		}

		le = apdu.setOutgoing();

		sha1.reset();
		hn = sha1.doFinal(hmacBuf, (short)0, (short)(64 + hn),
		    buffer, (short)0);

		hn = le > 0 ? (le > hn ? hn : le) : hn;
		apdu.setOutgoingLength(hn);
		apdu.sendBytes((short)0, hn);
	}

	private void
	handleGetSerial(APDU apdu)
	{
		final byte[] buffer = apdu.getBuffer();
		short len, le, i;
		le = apdu.setOutgoing();
		len = 0;

		for (i = (short)0; i < (short)serial.length; ++i)
			buffer[len++] = serial[i];

		len = le > 0 ? (le > len ? len : le) : len;
		apdu.setOutgoingLength(len);
		apdu.sendBytes((short)0, len);
	}
}
