/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of the  nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <string.h>

void util_str_lstrip(char *string) {
	size_t sz_old_str = strlen(string);
	size_t sz_new_str = 0;
	char *pos = string;

	while (*pos != '\0') {
		if (*pos == 9) {
			*pos = 0;
		} else if (*pos == 10) {
			*pos = 0;
		} else if (*pos == 11) {
			*pos = 0;
		} else if (*pos == 32) {
			*pos = 0;
		} else {
			break;
		}
		pos++;
	}
	if (pos != string) {
		sz_new_str = strlen(pos);
		memmove(string, pos, sz_new_str);
		memset(string + sz_new_str, '\0', (sz_old_str - sz_new_str));
	}
	return;
}

void util_str_rstrip(char *string) {
	char *pos = string;

	pos += strlen(string) - 1;
	while (pos >= string) {
		if (*pos == 9) {
			*pos = 0;
		} else if (*pos == 10) {
			*pos = 0;
		} else if (*pos == 11) {
			*pos = 0;
		} else if (*pos == 32) {
			*pos = 0;
		} else {
			break;
		}
		pos--;
	}
	return;
}

void util_str_strip(char *string) {
	util_str_rstrip(string);
	util_str_lstrip(string);
	return;
}
