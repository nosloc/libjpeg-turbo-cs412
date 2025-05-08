
#include <turbojpeg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
//#include <jpegint.h>
//#include <jpeglib.h>

#define NUMPF  4

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{

    // Make a writable copy
    uint8_t *mutable_data = (uint8_t *)malloc(size*8);
    if (!mutable_data) return 0;
    //memcpy(mutable_data, data, size);

    tjhandle handle = NULL;
    unsigned char *dstBuf = NULL; unsigned char *yuvBuf = NULL;
    int width = 0, height = 0, precision, sampleSize, pfi;
    int jpegSubsamp = 0;
    /* TJPF_RGB-TJPF_BGR share the same code paths, as do TJPF_RGBX-TJPF_XRGB and
        TJPF_RGBA-TJPF_ARGB.  Thus, the pixel formats below should be the minimum
        necessary to achieve full coverage. */
    enum TJPF pixelFormats[NUMPF] =
        { TJPF_RGB, TJPF_BGRX, TJPF_GRAY, TJPF_CMYK };

    if ((handle = tj3Init(TJINIT_DECOMPRESS)) == NULL)
        goto bailout;

    /* We ignore the return value of tj3DecompressHeader(), because malformed
        JPEG images that might expose issues in libjpeg-turbo might also have
        header errors that cause tj3DecompressHeader() to fail. */
    tj3DecompressHeader(handle, data, size);
    width = tj3Get(handle, TJPARAM_JPEGWIDTH);
    height = tj3Get(handle, TJPARAM_JPEGHEIGHT);
    precision = tj3Get(handle, TJPARAM_PRECISION);
    sampleSize = (precision > 8 ? 2 : 1);

    /* Ignore 0-pixel images and images larger than 1 Megapixel, as Google's
     OSS-Fuzz target for libjpeg-turbo did.  Casting width to (uint64_t)
     prevents integer overflow if width * height > INT_MAX. */
    if (width < 1 || height < 1 || (uint64_t)width * height > 1048576)
        goto bailout;

    tj3Set(handle, TJPARAM_SCANLIMIT, 500);
    //GET_INSTANCE(handle);
    //jpeg_set_defaults(handle->cinfo);

    for (pfi = 0; pfi < NUMPF; pfi++) {
        int w = width, h = height;
        int pf = pixelFormats[pfi], i, sum = 0;
    
        /* Test non-default decompression options on the first iteration. */
        if (!tj3Get(handle, TJPARAM_LOSSLESS)) {
          tj3Set(handle, TJPARAM_BOTTOMUP, pfi == 0);
          tj3Set(handle, TJPARAM_FASTUPSAMPLE, pfi == 0);
          tj3Set(handle, TJPARAM_FASTDCT, pfi == 0);
    
          /* Test IDCT scaling on the second iteration. */
          if (pfi == 1) {
            tjscalingfactor sf = { 3, 4 };
            tj3SetScalingFactor(handle, sf);
            w = TJSCALED(width, sf);
            h = TJSCALED(height, sf);
          } else
            tj3SetScalingFactor(handle, TJUNSCALED);
        }
    
        if ((dstBuf = (unsigned char *)tj3Alloc(w * h * tjPixelSize[pf])) == NULL)
          goto bailout;
        if ((yuvBuf =
             (unsigned char *)tj3Alloc(tj3YUVBufSize(w, 1, h,
                                                     jpegSubsamp))) == NULL)
          goto bailout;
        
        //(tjhandle*)handle->cinfo->quantize_color = TRUE;

        if (tjDecompressToYUV(handle, mutable_data, size, yuvBuf, 2048) == 0 &&
            tjDecodeYUV(handle, yuvBuf, 1, 3, dstBuf, w, 0, h, pf, 2048) == 0) {
          /* Touch all of the output pixels in order to catch uninitialized reads
             when using MemorySanitizer. */
          for (i = 0; i < w * h * tjPixelSize[pf]; i++)
            sum += dstBuf[i];
        } else
          goto bailout;
    
        free(dstBuf);
        dstBuf = NULL;
        free(yuvBuf);
        yuvBuf = NULL;
    
        /* Prevent the code above from being optimized out.  This test should never
           be true, but the compiler doesn't know that. */
        if (sum > 255 * 1048576 * tjPixelSize[pf])
          goto bailout;
      }
    /**
    handle->cinfo->data_precision = 8;
    hanlde->cinfo->master->lossless = 0;
    cinfo->out_color_components = 4; 
    cinfo->desired_number_of_colors = 256;
    cinfo->dither_mode = JDITHER_NONE;

    jinit_1pass_quantizer(j_decompress_ptr handle->cinfo);

    (*cinfo->cquantize->start_pass) (cinfo, FALSE);
    // (*cinfo->post->start_pass) (cinfo, JBUF_CRANK_DEST);
    // (*cinfo->main->start_pass) (cinfo, JBUF_CRANK_DEST);
    // start_pass, new_color_map, finish_pass, _color_quantize
    */
    bailout:
        free(dstBuf);
        free(yuvBuf);
        free(mutable_data);
        tj3Destroy(handle);
        return 0;

}

