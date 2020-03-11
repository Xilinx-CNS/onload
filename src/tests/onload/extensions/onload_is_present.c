/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/*
 * Build the file using the following command:
 *   $ gcc -oonload_is_present -lonload_ext onload_is_present.c
 *
 * Test by running the following two commands:
 *   $ ./onload_is_present
 *   Program running without Onload
 *   $ onload ./onload_is_present
 *   Program running with Onload
 *   $
 */
#include <stdio.h>

#include <onload/extensions.h>

int main(void)
{
  if( onload_is_present() )
    printf("Program running with Onload\n");
  else
    printf("Program running without Onload\n");

  return 0;
}
