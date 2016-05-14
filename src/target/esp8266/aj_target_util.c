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
#define AJ_MODULE TARGET_UTIL
#include "aj_target.h"
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <lwip/sockets.h>
#include <ajtcl/aj_debug.h>
#include <ajtcl/aj_util.h>

uint8_t dbgTARGET_UTIL = 0;

void AJ_Sleep(uint32_t ms)
{
    os_delay_us(ms*1000);
}

#ifndef NDEBUG
AJ_Status _AJ_GetDebugTime(AJ_Time* timer)
{
    /* Not implemented yet */
    AJ_Status status = AJ_ERR_RESOURCES;

    return status;
}
#endif

uint32_t AJ_GetElapsedTime(AJ_Time* timer, uint8_t cumulative)
{
    /* Not implemented yet */
    uint32_t elapsed = 10;
    return elapsed;
}
void AJ_InitTimer(AJ_Time* timer)
{
    struct timespec now;
    /* TODO get time from ntp server */
    timer->seconds = now.tv_sec;
    timer->milliseconds = now.tv_nsec / 1000000;

}

int32_t AJ_GetTimeDifference(AJ_Time* timerA, AJ_Time* timerB)
{
    int32_t diff;

    diff = (1000 * (timerA->seconds - timerB->seconds)) + (timerA->milliseconds - timerB->milliseconds);
    return diff;
}

void AJ_TimeAddOffset(AJ_Time* timerA, uint32_t msec)
{
    uint32_t msecNew;
    if (msec == -1) {
        timerA->seconds = -1;
        timerA->milliseconds = -1;
    } else {
        msecNew = (timerA->milliseconds + msec);
        timerA->seconds = timerA->seconds + (msecNew / 1000);
        timerA->milliseconds = msecNew % 1000;
    }
}


int8_t AJ_CompareTime(AJ_Time timerA, AJ_Time timerB)
{
    if (timerA.seconds == timerB.seconds) {
        if (timerA.milliseconds == timerB.milliseconds) {
            return 0;
        } else if (timerA.milliseconds > timerB.milliseconds) {
            return 1;
        } else {
            return -1;
        }
    } else if (timerA.seconds > timerB.seconds) {
        return 1;
    } else {
        return -1;
    }
}

uint64_t AJ_DecodeTime(char* der, const char* fmt)
{
    /* Not implemented yet*/
    return 0;
}

void* AJ_Malloc(size_t sz)
{
    return malloc(sz);
}
void* AJ_Realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

void AJ_Free(void* mem)
{
    if (mem) {
        free(mem);
    }
}

void AJ_MemZeroSecure(void* s, size_t n)
{
    volatile unsigned char* p = s;
    while (n--) *p++ = '\0';
    return;
}

/*
 * get a line of input from the the file pointer (most likely stdin).
 * This will capture the the num-1 characters or till a newline character is
 * entered.
 *
 * @param[out] str a pointer to a character array that will hold the user input
 * @param[in]  num the size of the character array 'str'
 * @param[in]  fp  the file pointer the sting will be read from. (most likely stdin)
 *
 * @return returns the same string as 'str' if there has been a read error a null
 *                 pointer will be returned and 'str' will remain unchanged.
 */
char*AJ_GetLine(char*str, size_t num, void*fp)
{
    char*p = fgets(str, num, fp);

    if (p != NULL) {
        size_t last = strlen(str) - 1;
        if (str[last] == '\n') {
            str[last] = '\0';
        }
    }
    return p;
}

uint8_t AJ_StartReadFromStdIn()
{
    return FALSE;
}

char* AJ_GetCmdLine(char* buf, size_t num)
{
    /* Not implemented yet */
    return NULL;
}

uint8_t AJ_StopReadFromStdIn()
{
    return FALSE;
}

#ifndef NDEBUG

/*
 * This is not intended, nor required to be particularly efficient.  If you want
 * efficiency, turn of debugging.
 */
int _AJ_DbgEnabled(const char* module)
{
    char buffer[128];
    char* env;

    strcpy(buffer, "ER_DEBUG_ALL");
    env = getenv(buffer);
    if (env && strcmp(env, "1") == 0) {
        return TRUE;
    }

    strcpy(buffer, "ER_DEBUG_");
    strcat(buffer, module);
    env = getenv(buffer);
    if (env && strcmp(env, "1") == 0) {
        return TRUE;
    }

    return FALSE;
}

#endif

uint16_t AJ_ByteSwap16(uint16_t x)
{
    return ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8);
}

uint32_t AJ_ByteSwap32(uint32_t x)
{
    return ((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8)
           | ((x & 0x00FF0000) >> 8) | ((x & 0xFF000000) >> 24);
}

uint64_t AJ_ByteSwap64(uint64_t x)
{
    return ((x & UINT64_C(0x00000000000000FF)) << 56)
           | ((x & UINT64_C(0x000000000000FF00)) << 40)
           | ((x & UINT64_C(0x0000000000FF0000)) << 24)
           | ((x & UINT64_C(0x00000000FF000000)) <<  8)
           | ((x & UINT64_C(0x000000FF00000000)) >>  8)
           | ((x & UINT64_C(0x0000FF0000000000)) >> 24)
           | ((x & UINT64_C(0x00FF000000000000)) >> 40)
           | ((x & UINT64_C(0xFF00000000000000)) >> 56);
}

AJ_Status AJ_IntToString(int32_t val, char* buf, size_t buflen)
{
    AJ_Status status = AJ_OK;
    int c = snprintf(buf, buflen, "%d", val);
    if (c <= 0 || c > buflen) {
        status = AJ_ERR_RESOURCES;
    }
    return status;
}

AJ_Status AJ_InetToString(uint32_t addr, char* buf, size_t buflen)
{
    AJ_Status status = AJ_OK;
    int c = snprintf((char*)buf, buflen, "%u.%u.%u.%u", (addr & 0xFF000000) >> 24, (addr & 0x00FF0000) >> 16, (addr & 0x0000FF00) >> 8, (addr & 0x000000FF));
    if (c <= 0 || c > buflen) {
        status = AJ_ERR_RESOURCES;
    }
    return status;
}

/*
static FILE* logFile = NULL;
static uint32_t logLim = 0;
*/

int AJ_SetLogFile(const char* file, uint32_t maxLen)
{
    /* Not implemented yet*/
    return 0;
}

void AJ_Printf(const char* fmat, ...)
{
    /* Not implemented yet*/
    return;
}
