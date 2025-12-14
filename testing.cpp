
/* Copyright Nash!Com, Daniel Nashed 2024-2025 - APACHE 2.0 see LICENSE */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>


#include "nshmailx.hpp"
#include "lib.hpp"

// Common Lorem Ipsum words
const char* szLoremWords[] =
{
    "lorem", "ipsum", "dolor", "sit", "amet",
    "consectetur", "adipiscing", "elit", "sed", "do",
    "eiusmod", "tempor", "incididunt", "ut", "labore",
    "et", "dolore", "magna", "aliqua", "enim",
    "ad", "minim", "veniam", "quis", "nostrud",
    "exercitation", "ullamco", "laboris", "nisi", "aliquip",
    "ex", "ea", "commodo", "consequat"
};

#define WORD_COUNT (sizeof(szLoremWords) / sizeof(szLoremWords[0]))
#define MAX_SUFFIX_LEN 3
#define MAX_NUMBER_STR 32


char* GenerateLoremBuffer (size_t TargetLen)
{
    char szBlank[]        = " ";
    char szDot[]          = ". ";
    char szNewParagraph[] = ".\n";

    char *pszBuffer   = NULL;
    char *pPos        = NULL;
    char *pszSuffix   = NULL;

    const char *pszWord = NULL;

    size_t MaxWordLen = 0;
    size_t WordLen    = 0;
    size_t WordCount  = 0;
    size_t len        = 0;
    size_t i          = 0;
    int    bytes      = 0;

    bool   bNewSentence = true;

    if (TargetLen < 1)
        return NULL;

    pszBuffer = (char*)malloc(TargetLen + MAX_SUFFIX_LEN + 1);  // Room for null terminator and suffix

    if (NULL == pszBuffer)
    {
        return NULL;
    }

    pszBuffer[0] = '\0';
    pPos = pszBuffer;

    // Calculate longest word length dynamically
    for (i=0; i < WORD_COUNT; ++i)
    {
        WordLen = strlen(szLoremWords[i]);

        if (WordLen > MaxWordLen)
        {
            MaxWordLen = WordLen;
        }
    }

    while ( (len + MaxWordLen) < TargetLen)
    {
        pszWord = szLoremWords[rand() % WORD_COUNT];

        if (WordCount < 7)
        {
            /* Only if sentence has 7 words or more */
            pszSuffix = szBlank;
        }
        else if (0 == (rand() % 42))
        {
            pszSuffix = szNewParagraph;
        }
        else if (0 == (rand() % 21))
        {
            pszSuffix = szDot;
        }
        else
        {
            pszSuffix = szBlank;
        }

        if (bNewSentence)
            bytes = snprintf (pPos, TargetLen-len, "%c%s%s", toupper(*pszWord), pszWord + 1, pszSuffix);
        else
            bytes = snprintf (pPos, TargetLen-len, "%s%s", pszWord, pszSuffix);

        if (pszSuffix == szBlank)
        {
            bNewSentence = false;
            WordCount++;
        }
        else
        {
            bNewSentence = true;
            WordCount = 0;
        }

        if (bytes <= 0 || (size_t)bytes >= (TargetLen - len))
            break;

        len  += bytes;
        pPos += bytes;

    } // while


    if (pPos != pszBuffer && !bNewSentence && *(pPos - 1) == ' ')
        *(pPos - 1) = '.';

    return pszBuffer;
}


int SendTestMessages(const char *pszHostname,
                     const char *pszMailer,
                     const char *pszSmtpServerAddress,
                     const char *pszFrom,
                     const char *pszFromName,
                     const char *pszSendTo,
                     const char *pszCopyTo,
                     const char *pszBlindCopyTo,
                     const char *pszSubject,
                     const char *pszBody,
                     const char *pszBodyFile,
                     const char *pszAttachmenFilePath,
                     const char *pszAttachmentName,
                     const char *pszAttachmentBuffer,
                     const char *pszCipherList,
                     int  Port,
                     size_t Options,
                     size_t TestMessageCount,
                     size_t TestBodySize,
                     size_t TestAttSize)
{
    int    rc        = 0;
    size_t count     = 0;
    size_t TotalSize = 0;
    long   diff_ms   = 0;

    char   *pszLocalBodyBuffer = NULL;
    char   *pszLocalAttachmentBuffer = NULL;
    char   szSubject[4096] = {0};
    char   szNumStr[MAX_NUMBER_STR+1] = {0};
    char   szPerformanceString[MAX_NUMBER_STR+1] = {0};

    struct timespec start = {0};
    struct timespec end   = {0};

    if ( (0 == TestBodySize) && ( 0 == TestAttSize) )
        TestBodySize = 1024;

    for (count = 1; count <= TestMessageCount; count++)
    {
        if (TestAttSize)
        {
            pszLocalAttachmentBuffer = GenerateLoremBuffer (TestAttSize);
            pszAttachmentBuffer = pszLocalAttachmentBuffer;

            TotalSize = TestAttSize;
        }
        else if (TestBodySize)
        {
            pszLocalBodyBuffer = GenerateLoremBuffer (TestBodySize);
            pszBody = pszLocalBodyBuffer;

            TotalSize = TestBodySize;
        }

        snprintf (szSubject, sizeof (szSubject), "nshmailx test mail #%ld", count);
        pszSubject = szSubject;

        clock_gettime(CLOCK_MONOTONIC, &start);

        rc = SendSmtpMessage (pszHostname,
                              pszMailer,
                              pszSmtpServerAddress,
                              pszFrom,
                              pszFromName,
                              pszSendTo,
                              pszCopyTo,
                              pszBlindCopyTo,
                              pszSubject,
                              pszBody,
                              pszBodyFile,
                              pszAttachmenFilePath,
                              pszAttachmentName,
                              pszAttachmentBuffer,
                              pszCipherList,
                              NULL,
                              Port,
                              Options);

        clock_gettime (CLOCK_MONOTONIC, &end);
        diff_ms = time_diff_ms(start, end);

        GetBytesHumanReadable (TotalSize, sizeof(szNumStr), szNumStr);
        CalculatePerformanceString (diff_ms, TotalSize, sizeof(szPerformanceString), szPerformanceString);
        printf ("Mail send in %1.1f sec (Size: %s, Speed: %s)\n", (double)diff_ms / 1000.0, szNumStr, szPerformanceString);

        // Release buffers if allocated

        if (pszLocalAttachmentBuffer)
        {
            free (pszLocalAttachmentBuffer);
            pszLocalAttachmentBuffer = NULL;
        }

        if (pszLocalBodyBuffer)
        {
            free (pszLocalBodyBuffer);
            pszLocalBodyBuffer = NULL;
        }

        if (rc)
        {
            break;
        }

    } // for

    return rc;
}

