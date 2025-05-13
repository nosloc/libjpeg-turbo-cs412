/*
 * Copyright (C)2021-2024 D. R. Commander.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of the libjpeg-turbo Project nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS",
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <turbojpeg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
 
#define NUMTESTS  7

struct test {
  enum TJPF pf;
  enum TJSAMP subsamp;
  int quality;
};
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
 {  

    tjhandle handle = NULL;
    unsigned char *srcBuf = NULL, *dstBuf = NULL;
    short *srcBuf12 = NULL;
    short *dstBuf12 = NULL;
    unsigned short *srcBuf16 = NULL;
    unsigned short *dstBuf16 = NULL;
    int width = 0, height = 0, fd = -1, ti;
    char filename[FILENAME_MAX] = { 0 };
    struct test tests[NUMTESTS] = {
        { TJPF_RGB, TJSAMP_444, 100 },
        { TJPF_BGR, TJSAMP_422, 90 },
        { TJPF_RGBX, TJSAMP_420, 80 },
        { TJPF_BGRA, TJSAMP_411, 70 },
        { TJPF_XRGB, TJSAMP_GRAY, 60 },
        { TJPF_GRAY, TJSAMP_GRAY, 50 },
        { TJPF_CMYK, TJSAMP_440, 40 }
    };

    snprintf(filename, FILENAME_MAX, "/tmp/libjpeg-turbo_saveImage_fuzz.XXXXXX");
    if ((fd = mkstemp(filename)) < 0 || write(fd, data, size) < 0)
        goto bailout;

    if ((handle = tj3Init(TJINIT_TRANSFORM)) == NULL)
        goto bailout;

    for (ti = 0; ti < NUMTESTS; ti++) {
        int pf = tests[ti].pf;
        size_t dstSize = 0, maxBufSize, i, sum = 0;

        /* Test non-default options on specific iterations. */
        tj3Set(handle, TJPARAM_BOTTOMUP, ti == 0);
        tj3Set(handle, TJPARAM_NOREALLOC, ti != 2);
        //tj3Set(handle, TJPARAM_PRECISION, tests[ti].precision);
        tj3Set(handle, TJPARAM_RESTARTROWS, ti == 0 || ti == 6 ? 1 : 0);
        
        // test with 8
        if ((srcBuf = tj3LoadImage8(handle, filename, &width, 1, &height,
                                     &pf)) == NULL)
            continue;
        
        if (width <= 0 || height <= 0 || width > 10000 || height > 10000) {
            tj3Free(srcBuf);
            srcBuf = NULL;
            continue;
        }
        dstSize = maxBufSize = tj3JPEGBufSize(width, height, tests[ti].subsamp);
        if (tj3Get(handle, TJPARAM_NOREALLOC)) {
            if ((dstBuf = (unsigned char *)tj3Alloc(dstSize)) == NULL)
                goto bailout;
        } else
            dstBuf = NULL;

        tj3SaveImage8(handle, filename, dstBuf, width, 0, height, pf);
        free(dstBuf);
        dstBuf = NULL;
        tj3Free(srcBuf);
        srcBuf = NULL;
        
        // test with 12
        if ((srcBuf12 = tj3LoadImage12(handle, filename, &width, 1, &height,
                                     &pf)) == NULL)
            continue;
        if (width <= 0 || height <= 0 || width > 10000 || height > 10000) {
            tj3Free(srcBuf12);
            srcBuf12 = NULL;
            continue;
        }
        dstSize = maxBufSize = tj3JPEGBufSize(width, height, tests[ti].subsamp);
        if (tj3Get(handle, TJPARAM_NOREALLOC)) {
            if ((dstBuf12 = (short *)tj3Alloc(dstSize)) == NULL)
                goto bailout;
        } else
            dstBuf12 = NULL;

        tj3SaveImage12(handle, filename, dstBuf12, width, 0, height, pf);
        free(dstBuf12);
        dstBuf12 = NULL;
        tj3Free(srcBuf12);
        srcBuf12 = NULL;

        // test with 16
        if ((srcBuf16 = tj3LoadImage16(handle, filename, &width, 1, &height,
                                     &pf)) == NULL)
            continue;
        if (width <= 0 || height <= 0 || width > 10000 || height > 10000) {
            tj3Free(srcBuf16);
            srcBuf16 = NULL;
            continue;
        }
        dstSize = maxBufSize = tj3JPEGBufSize(width, height, tests[ti].subsamp);
        if (tj3Get(handle, TJPARAM_NOREALLOC)) {
            if ((dstBuf16 = (unsigned short *)tj3Alloc(dstSize)) == NULL)
                goto bailout;
        } else
            dstBuf12 = NULL;

        tj3SaveImage16(handle, filename, dstBuf16, width, 0, height, pf);
        free(dstBuf16);
        dstBuf16 = NULL;
        tj3Free(srcBuf);
        srcBuf16 = NULL;
    }

bailout:
    free(dstBuf);
    tj3Free(srcBuf);
    free(dstBuf12);
    tj3Free(srcBuf12);
    free(dstBuf16);
    tj3Free(srcBuf16);
    if (fd >= 0) {
        close(fd);
        if (strlen(filename) > 0) unlink(filename);
    }
    tj3Destroy(handle);
    return 0;
 }
 
