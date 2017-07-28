/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Alex Wilson <alex@cooperi.net>
 */

package net.cooperi.ykotpapplet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class SlotConfig
{
	public static final short FIXED_SIZE = (short)16;
	public static final short KEY_SIZE = (short)16;
	public static final short KEY_SIZE_OATH = (short)20;
	public static final short ACC_CODE_SIZE = (short)6;
	public static final short UID_SIZE = (short)6;

	public static final short CFG_FIXED_OFFS = 0;
	public static final short CFG_UID_OFFS = FIXED_SIZE;
	public static final short CFG_KEY_OFFS =
	    (short)(CFG_UID_OFFS + UID_SIZE);
	public static final short CFG_ACC_CODE_OFFS =
	    (short)(CFG_KEY_OFFS + KEY_SIZE);
	public static final short CFG_FIXED_SIZE_OFFS =
	    (short)(CFG_ACC_CODE_OFFS + ACC_CODE_SIZE);
	public static final short CFG_EXT_FLAGS_OFFS =
	    (short)(CFG_FIXED_SIZE_OFFS + 1);
	public static final short CFG_TKT_FLAGS_OFFS =
	    (short)(CFG_EXT_FLAGS_OFFS + 1);
	public static final short CFG_CFG_FLAGS_OFFS =
	    (short)(CFG_TKT_FLAGS_OFFS + 1);
	public static final short CFG_CRC_OFFS =
	    (short)(CFG_CFG_FLAGS_OFFS + 3);
	public static final short CFG_SIZE = (short)(CFG_CRC_OFFS + 2);

	public static final byte TKTFLAG_CHAL_RESP = (byte)0x40;
	public static final byte CFGFLAG_CHAL_MASK = (byte)0x22;
	public static final byte CFGFLAG_IS_CHAL_RESP = (byte)0x20;
	public static final byte CFGFLAG_CHAL_YUBICO = (byte)0x20;
	public static final byte CFGFLAG_CHAL_HMAC = (byte)0x22;
	public static final byte CFGFLAG_HMAC_LT64 = (byte)0x04;

	public byte[] key = null;
	public byte[] accCode = null;
	public boolean programmed = false;

	public
	SlotConfig()
	{
		key = new byte[64];
	}

	public byte fixedSize = (byte)0;
	public byte extFlags = (byte)0;
	public byte tktFlags = (byte)0;
	public byte cfgFlags = (byte)0;

	public boolean
	read(byte[] input, short off, short len)
	{
		byte newExtFlags = input[(short)(off + CFG_EXT_FLAGS_OFFS)];
		byte newTktFlags = input[(short)(off + CFG_TKT_FLAGS_OFFS)];
		byte newCfgFlags = input[(short)(off + CFG_CFG_FLAGS_OFFS)];

		if (len < CFG_SIZE) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return (false);
		}

		if (newTktFlags != TKTFLAG_CHAL_RESP ||
		    (byte)(newCfgFlags & CFGFLAG_CHAL_HMAC) == 0) {
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			return (false);
		}

		if ((byte)(newCfgFlags & CFGFLAG_HMAC_LT64) == 0) {
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
			return (false);
		}

		extFlags = newExtFlags;
		tktFlags = newTktFlags;
		cfgFlags = newCfgFlags;
		fixedSize = input[(short)(off + CFG_FIXED_SIZE_OFFS)];

		if (accCode != null) {
			if (len < (short)(CFG_SIZE + ACC_CODE_SIZE)) {
				ISOException.throwIt(
				    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				return (false);
			}

			if (Util.arrayCompare(accCode, (short)0, input,
			    (short)(off + CFG_SIZE), ACC_CODE_SIZE) != 0) {
				ISOException.throwIt(
				    ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				return (false);
			}
		}

		boolean accCodeZero = true;
		short i = (short)(off + CFG_ACC_CODE_OFFS);
		short lim = (short)(i + ACC_CODE_SIZE);
		for (; i < lim; ++i) {
			if (input[i] != (byte)0) {
				accCodeZero = false;
				break;
			}
		}

		if (!accCodeZero) {
			if (accCode == null)
				accCode = new byte[ACC_CODE_SIZE];
			Util.arrayCopy(input, (short)(off + CFG_ACC_CODE_OFFS),
			    accCode, (short)0, ACC_CODE_SIZE);
		}

		Util.arrayCopy(input, (short)(off + CFG_KEY_OFFS), key,
		    (short)0, KEY_SIZE);
		Util.arrayCopy(input, (short)(off + CFG_UID_OFFS), key,
		    KEY_SIZE, (short)(KEY_SIZE_OATH - KEY_SIZE));

		programmed = true;
		return (true);
	}
}
