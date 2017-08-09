/**
 *
 * @file 
 * @brief   Button example for TM1638 based displays
 * @author  Martin Oldfield <ex-tm1638@mjo.tc>
 * @version 0.1
 *
 * @section DESCRIPTION
 *
 * A simple example showing how to read buttons.
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

#include <bcm2835.h>

#include "tm1638.h"

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

  tm1638_set_7seg_text(t, "Buttons!", 0x00);
  
  while(1)
    {
      uint8_t  x = tm1638_read_8buttons(t);
      tm1638_set_8leds(t, 0, x);

      delay(10);
    }

  tm1638_free(&t);

  return 0;
}

/** @endcond */
