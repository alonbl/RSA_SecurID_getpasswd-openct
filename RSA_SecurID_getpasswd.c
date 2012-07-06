/*
    RSA_SecurID_getpasswd.c: get the one-use password from a RSA sid-800 token
    Copyright (C) 2006   Ludovic Rousseau <ludovic.rousseau@free.fr>
    Copyright (C) 2012   Alon Bar-Lev <alon.barlev@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc., 51
	Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openct/openct.h>
#include <openct/error.h>

int main(void) {
	unsigned char securid_atr[] = { 0x3b, 0x0f, 0x80, 0x22, 0x15, 0xe1, 0x5a, 0x00, 0x20, 0x00, 0x30, 0x21, 0x03, 0x31, 0x21, 0x03, 0x00 };
	unsigned char cmd1[] = { 0x00, 0xa4, 0x04, 0x00, 0x0a, 0xa0, 0x00, 0x00, 0x00, 0x63, 0x86, 0x53, 0x49, 0x44, 0x01};
	unsigned char cmd2[] = { 0x80, 0x56, 0x00, 0x00, 0x04 };
	unsigned char cmd3[] = { 0x80, 0x48, 0x00, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff };
	unsigned char cmd4[] = { 0x80, 0x44, 0x00, 0x00, 0x05};
	unsigned char atr[64];
	int atr_len;
	unsigned char res[1024];
	ct_handle *h;
	ct_lock_handle lock1 = 0, lock2 = 0;
	unsigned int opt_slot = 0;
	int exit_code = 1;
	int status;
	int rc;
	int i;

	for (i = 0; i < OPENCT_MAX_READERS; i++) {
		if (
			(h = ct_reader_connect(i)) != NULL &&
			ct_card_lock(h, opt_slot, IFD_LOCK_SHARED, &lock1) >= 0 &&
			ct_card_status(h, opt_slot, &status) >= 0 &&
			(status & IFD_CARD_PRESENT) != 0 &&
			(atr_len = ct_card_reset(h, opt_slot, atr, sizeof(atr))) >= 0 &&
			sizeof(securid_atr) == (size_t)atr_len &&
			!memcmp(securid_atr, atr, atr_len)
		) {
			break;
		}

		if (lock1 != 0) {
			ct_card_unlock(h, 0, lock1);
			lock1 = 0;
		}

		if (h != NULL) {
			ct_reader_disconnect(h);
			h = NULL;
		}
	}
	if (i == OPENCT_MAX_READERS) {
		fprintf(stderr, "no RSA SecurID found\n");
		goto cleanup;
	}

	if ((rc = ct_card_lock(h, opt_slot, IFD_LOCK_EXCLUSIVE, &lock2)) < 0) {
		fprintf(stderr, "ct_card_lock: err=%d\n", rc);
		goto cleanup;
	}

	rc = ct_card_transact(h, opt_slot, cmd1, sizeof(cmd1), res, sizeof(res));
	if (rc < 0) {
		fprintf(stderr, "card communication failure (1), err=%d\n", rc);
		goto cleanup;
	}

	if ((rc != 2) || (res[0] != 0x90) || (res[1] != 0x00)) {
		fprintf(stderr, "cmd1 failed (%d): %02X%02X\n", rc, res[rc-2],
			res[rc-1]);
		goto cleanup;
	}

	rc = ct_card_transact(h, opt_slot, cmd2, sizeof(cmd2), res, sizeof(res));
	if (rc < 0) {
		fprintf(stderr, "card communication failure (2), err=%d\n", rc);
		goto cleanup;
	}

	if ((rc != 6) || (res[4] != 0x90) || (res[5] != 0x00)) {
		fprintf(stderr, "cmd2 failed (%d) : %02X%02X\n", rc, res[rc-2],
			res[rc-1]);
		goto cleanup;
	}

	/* get the argument for cmd3 from result of cmd2 */
	memcpy(cmd3+5, res, 4);

	/* non ISO APDU */
	rc = ct_card_transact(h, opt_slot, cmd3, sizeof(cmd3), res, sizeof(res));
	if (rc < 0) {
		fprintf(stderr, "card communication failure (3), err=%d\n", rc);
		goto cleanup;
	}

	if ((rc != 2) || (res[0] != 0x90) || (res[1] != 0x00)) {
		fprintf(stderr, "cmd3 failed (%d): %02X%02X\n", rc, res[rc-2],
			res[rc-1]);
		goto cleanup;
	}

	/* non iSO APDU */
	rc = ct_card_transact(h, opt_slot, cmd4, sizeof(cmd4), res, sizeof(res));
	if (rc < 0) {
		fprintf(stderr, "card communication failure (4), err=%d\n", rc);
		goto cleanup;
	}

	if ((rc != 7) || (res[5] != 0x90) || (res[6] != 0x00)) {
		fprintf(stderr, "cmd4 failed (%d): %02X%02X\n", rc, res[rc-2],
			res[rc-1]);
		goto cleanup;
	}

	printf("%02X%02X%02X\n", res[2], res[3], res[4]);
	exit_code = 0;

cleanup:

	if (lock2 != 0) {
		ct_card_unlock(h, 0, lock2);
	}
	if (lock1 != 0) {
		ct_card_unlock(h, 0, lock1);
	}
	if (h != NULL) {
		ct_reader_disconnect(h);
	}
	sleep(1);
	return exit_code;
}
