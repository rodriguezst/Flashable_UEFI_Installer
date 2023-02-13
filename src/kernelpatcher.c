/* Copyright 2023 Molly Sophia<mollysophia379@gmail.com>

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright 
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyri
-ght notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the dis
-tribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTO
    -RS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT
    NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FIT
    -NESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
    THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, IN
    -DIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
    OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPT
    -ION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHE
    -RWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN 
    IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define abort(msg) \
{ \
    printf(msg"\n"); \
    return -1; \
} 

FILE *kernel, *bootshim;
long long bootshimsize = 0, kernelsize = 0;
int main(int argc, char** argv) {
    unsigned char tmp[16];
    bool uncompressed_img = 0;
    int kernel_start = 0;
    long long payloadsize = 0;

    if(argc < 4) abort("usage: kernelpatcher <kernel> <bootshim> <payload size>");

    kernel = fopen(argv[1], "rb+");
    if(!kernel) abort("Failed to read kernel file");
    bootshim = fopen(argv[2], "rb+");
    if(!bootshim) {
        fclose(kernel);
        abort("Failed to read bootshim file");
    }

    fseek(bootshim, 0, SEEK_END);
    bootshimsize = ftell(bootshim);
    if(!bootshimsize) {
        fclose(bootshim);
        fclose(kernel);
        abort("Failed to get bootshim size");
    }

    if(bootshimsize % 4 != 0) {
        fclose(bootshim);
        fclose(kernel);
        abort("Invalid bootshim file");
    }

    sscanf(argv[3], "%llu", &payloadsize);
    if(!payloadsize) {
        fclose(bootshim);
        fclose(kernel);
        abort("No valid payloadsize supplied");
    }

    unsigned char *buffer = malloc(bootshimsize);
    if(!buffer) {
        fclose(bootshim);
        fclose(kernel);
        abort("Failed to allocate buffer");
    }

    fseek(bootshim, 0, SEEK_SET);
    fread(buffer, 4, bootshimsize / 4, bootshim);

    // check if it's on a qcom special Image-dtb format
    fseek(kernel, 0, SEEK_SET);
    fread(tmp, 8, 2, kernel);
    if(!strncmp(tmp, "UNCOMPRESSED_IMG", 16)) {
        uncompressed_img = true;
        kernel_start = 0x14;
    }

    // check if it's an edk2-msm patched kernel
    fseek(kernel, kernel_start + 0x40, SEEK_SET);
    fread(tmp, 8, 1, kernel);
    if(!strncmp(tmp, "EDK2-MSM", 8)) {
        printf("Patched kernel detected! Updating.\n");

        // copy the second instruction that jump to actual kernel
        fseek(kernel, kernel_start + 4, SEEK_SET);
        fread(buffer + 4, 4, 1, kernel);

        // copy the kernel size region
        fseek(kernel, kernel_start + 0x10, SEEK_SET);
        fread(buffer + 0x10, 8, 1, kernel);

        fseek(kernel, kernel_start + 0x30, SEEK_SET);
        fread(buffer + 0x30, 8, 1, kernel);
    } else {
        printf("Stock kernel detected! Patching.\n");

        fseek(kernel, 0, SEEK_END);
        kernelsize = ftell(kernel) - kernel_start;
        if(!kernelsize) {
            free(buffer);
            fclose(bootshim);
            fclose(kernel);
            abort("Failed to get kernel size");
        }
        
        // read the first two instructions of the stock kernel
        fseek(kernel, kernel_start, SEEK_SET);
        fread(tmp, 8, 1, kernel);
        // for(int i = 0; i < 8; i++) {
        //     printf("%02x ", tmp[i]);
        // }
        if(tmp[3] == 0x14) {
            // found jump at the first instruction
            long long addr = (tmp[0] | (tmp[1] << 8) | (tmp[2] << 16)) - 1;
            tmp[0] = addr & 0xff;
            tmp[1] = (addr >> 8) & 0xff;
            tmp[2] = (addr >> 16) & 0xff;
            memcpy(buffer + 4, tmp, 4);
        } else if(tmp[7] == 0x14) {
            fseek(kernel, kernel_start + 4, SEEK_SET);
            fread(buffer + 4, 8, 1, kernel);
        } else {
            free(buffer);
            fclose(bootshim);
            fclose(kernel);
            abort("Invalid kernel file!");
        }
        
        // fill in the kernel size for calculating UEFI position
        memset(tmp, 0, sizeof(tmp));
        tmp[0] = kernelsize & 0xff;
        tmp[1] = (kernelsize >> 8) & 0xff;
        tmp[2] = (kernelsize >> 16) & 0xff;
        tmp[3] = (kernelsize >> 24) & 0xff;
        tmp[4] = (kernelsize >> 32) & 0xff;
        tmp[5] = (kernelsize >> 40) & 0xff;
        tmp[6] = (kernelsize >> 48) & 0xff;
        tmp[7] = (kernelsize >> 56) & 0xff;

        memcpy(buffer + 0x10, tmp, 8);
        memcpy(buffer + 0x30, tmp, 8);
    }

    // for(int i = 0; i < bootshimsize; i++) {
    //     if(i%16 == 0) printf("\n");
    //     printf("%02x ", *(buffer+i));
    // }

    fseek(kernel, kernel_start, SEEK_SET);
    printf("Updated %lu bytes in kernel header\n",
        fwrite(buffer, 4, bootshimsize / 4, kernel));

    if(uncompressed_img) {
        tmp[0] = (kernelsize + payloadsize) & 0xff;
        tmp[1] = ((kernelsize + payloadsize) >> 8) & 0xff;
        tmp[2] = ((kernelsize + payloadsize) >> 16) & 0xff;
        tmp[3] = ((kernelsize + payloadsize) >> 24) & 0xff;

        fseek(kernel, 0x10, SEEK_SET);
        fwrite(tmp, 4, 1, kernel);
    }

    fclose(bootshim);
    fclose(kernel);
    free(buffer);
    return 0;
} 