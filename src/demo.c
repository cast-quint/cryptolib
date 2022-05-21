/*
 * Dimitrios Koropoulis 3967
 * csd3967@csd.uoc.gr
 * CS457 - Spring 2022
 * demo.c
 */

#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char** argv) {

    int live_crack = 0;

    if (argc == 2 && strcmp(argv[1], "-c") == 0) {
        live_crack = 1;
    }

    /* if true, the OTP cracks the two words on the spot */
    otp_demo(live_crack);

    rail_fence_demo();

    beaufort_demo();

    affine_demo();

    feistel_demo();

    return EXIT_SUCCESS;
}

