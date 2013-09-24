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

/* dispatch routines */
DWORD command_add_vendor(cJSON *parameters, cJSON *result);
DWORD command_exec_query(cJSON *parameters, cJSON *result);
DWORD command_get_credentials(cJSON *parameters, cJSON *result);
DWORD command_pay_vendor(cJSON *parameters, cJSON *result);
DWORD command_status(cJSON *parameters, cJSON *result);

/* dispatch data types */
typedef DWORD (*DISPATCH_ROUTINE)(cJSON *parameters, cJSON *result);

typedef struct parameters {
	LPCSTR              name;
	BYTE                type;
} Parameters;

typedef struct command {
	LPCSTR              method_name;
	DISPATCH_ROUTINE    handler;
	Parameters*         required_parameters;
} Command;

/* dispatch table parameter definitions */
Parameters parameters_add_vendor[] = {
	{ "vendor_id", cJSON_String },
	{ "name",      cJSON_String },
	{ "addr1",     cJSON_String },
	{ "city",      cJSON_String },
	{ "state",     cJSON_String },
	{ "zipcode",   cJSON_String },
	{ NULL, 0 },
};

Parameters parameters_exec_query[] = {
	{ "query", cJSON_String },
	{ NULL, 0 },
};

Parameters parameters_pay_vendor[] = {
	{ "vendor_id", cJSON_String },
	{ "amount",    cJSON_String },
	{ "checkbook", cJSON_String },
	{ NULL, 0 },
};

/* primary command dispatch table definition */
Command dispatch_table[] = {
	{ "add_vendor",      command_add_vendor,      parameters_add_vendor },
	{ "exec_query",      command_exec_query,      parameters_exec_query },
	{ "get_credentials", command_get_credentials, NULL },
	{ "pay_vendor",      command_pay_vendor,      parameters_pay_vendor },
	{ "status",          command_status,          NULL },
	{ NULL, NULL, NULL },
};
