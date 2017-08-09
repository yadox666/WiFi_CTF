/**
 *
 * @file 
 * @brief   Clock for TM1638 based displays
 * @author  Martin Oldfield <ex-tm1638@mjo.tc>
 * @version 0.1
 *
 * @section DESCRIPTION
 *
 * A simple digital clock example program for the TM1638.
 *
 * @section HARDWARE
 *
 * The code hard wires pin connections:
 *
 *    * data: GPIO 17
 *    * clock: GPIO 21
 *    * strobe: GPIO 22
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 */

/** @cond NEVER */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <bcm2835.h>
#include <tm1638.h>

int main(int argc, char *argv[])
{
  tm1638_p t;

  if (!bcm2835_init())
    {
      printf("Unable to initialize BCM library\n");
      return -1;
    }

  t = tm1638_alloc(17, 21, 22);
  if (!t)
    {
      printf("Unable to allocate TM1638\n");
      return -2;
    }

  while(1)
    {
      time_t now    = time(NULL);
      struct tm *tm = localtime(&now);

      char text[10];
      snprintf(text, 9, "%02d %02d %02d", tm->tm_hour, tm->tm_min, tm->tm_sec);

      tm1638_set_7seg_text(t, text, 0x00);
      delay(100);
    }

  return 0;
}
