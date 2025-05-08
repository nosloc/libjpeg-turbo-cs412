
#include <turbojpeg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <jpegint.h>
#include <jpeglib.h>


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    tjhandle handle = NULL;
    void *dstBuf = NULL;
    int width = 0, height = 0, precision, sampleSize, pfi;
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
    GET_INSTANCE(handle);


    jpeg_set_defaults(handle->cinfo);

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

    bailout:
        tj3Destroy(handle);
        return 0;


}

