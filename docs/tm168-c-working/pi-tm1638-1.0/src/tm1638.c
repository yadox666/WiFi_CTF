/**
 *
 * @file 
 * @brief   A simple interface to TM1638 based displays for the Raspberry Pi.
 * @author  Martin Oldfield <ex-tm1638@mjo.tc>
 * @version 0.1
 *
 * @section DESCRIPTION
 *
 * A simple interface to the TM1638 based displays for the Raspberry Pi.
 *
 * Dealextreme, doubtless amongst others, sell small boards with eight
 * seven-segment displays, eight red-green LEDs and eight push buttons
 * for less than $10.
 *
 * The boards are basically just the LEDs and switches, and a TM1638
 * driver chip. This sits on a two-wire serial bus which makes it
 * fairly easy to connect the boards to a computer/microcontroller of
 * your choice. Of course, one needs a little bit of software. This is
 * such a library for the Raspberry Pi.
 *
 * This is the C source file implementing the library, and so this
 * documentation includes information only relevant to the
 * implementation. If you're just using the library, read the tm1638.h
 * documentation instead.
 *
 * @section ISSUES
 *
 * 1. The code makes the data line into an output by default, turning
 *    it into an input only when reading data. It should probably be
 *    the other way round: an input unless we're actually driving something.
 * 2. Some delays are needed or some pulses are too fast. The delays
 *    are all somewhat arbitrary, and whilst they work for me, I don't
 *    claim that they are optimal.
 * 3. The packaging is rather clunky: I don't grok autotools very well!
 *
 * @section REFERENCES
 *
 * Inevitably people have already done all this for with an Arduino,
 * and that made it easier to write this:
 *
 * 1. John Boxall wrote [a blog about
 * it.](http://tronixstuff.wordpress.com/2012/03/11/arduino-and-tm1638-led-display-modules/)
 * 2. Ricardo Batista wrote [a library to do
 * it.](http://code.google.com/p/tm1638-library/)
 * 3. [Marc](http://www.freetronics.com) (via John above) [found a
 * datasheet.](http://dl.dropbox.com/u/8663580/TM1638English%20version.pdf)
 *
 * This isn't really a port of Ricardo's code: I wanted a different
 * API.  However, I did copy his nice 7-segment font, and his code was
 * very helpful when it came to understanding the data-sheet. 
 * 
 * Thank you to everyone.
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
     
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <bcm2835.h>

#include "tm1638.h"

/**
 * A struct representing the TM1638 board.
 *
 * If you're just using the library, you shouldn't care how this
 * is defined: it might change under your feet.
 */
struct tm1638_tag
{
  uint8_t data;       /**< The pin which is connected to the TM1638's data line */
  uint8_t clock;      /**< The pin which is connected to the TM1638's clock line */
  uint8_t strobe;     /**< The pin which is connected to the TM1638's strobe line */

  uint8_t intensity;  /**< The current LED brightness */
  bool    enable;     /**< true iff we're enabled */
};

static void tm1638_send_raw(const tm1638_p t, uint8_t x);
static uint8_t tm1638_receive_raw(const tm1638_p t);
static void tm1638_send_command(const tm1638_p t, uint8_t x);
static void tm1638_send_data(const tm1638_p t, uint8_t addr, uint8_t data);
static void tm1638_send_config(const tm1638_p t);
static uint8_t tm1638_calc_config(const tm1638_p t);

/* See tm1638.h */
tm1638_p tm1638_alloc(uint8_t data, uint8_t clock, uint8_t strobe)
{
  /* The delays in this code are somewhat arbitrary: they work for me
     but I make no claims that they are optimal or robust */

  tm1638_p t = malloc(sizeof(tm1638));
  if (!t)
    return NULL;

  t->data   = data;
  t->clock  = clock;
  t->strobe = strobe;
  
  t->intensity = 7;
  t->enable    = true;

  bcm2835_gpio_fsel(t->data, BCM2835_GPIO_FSEL_OUTP);
  bcm2835_gpio_fsel(t->clock,    BCM2835_GPIO_FSEL_OUTP);
  bcm2835_gpio_fsel(t->strobe,   BCM2835_GPIO_FSEL_OUTP);

  bcm2835_gpio_write(t->strobe, HIGH);
  bcm2835_gpio_write(t->clock,  HIGH);
  delayMicroseconds(1);
  
  tm1638_send_config(t);

  tm1638_send_cls(t);

  return t;
}

/* See tm1638.h */
void tm1638_free(tm1638_p *t)
{
  free(*t);
  *t = NULL;
} 

/* See tm1638.h */
void tm1638_enable(tm1638_p t, bool enable)
{
  t->enable = enable;
  tm1638_send_config(t);
}

/* See tm1638.h */
void tm1638_set_intensity(tm1638_p t, uint8_t intensity)
{
  /* maximum intensity is 7 */
  if (intensity > 7)
    intensity = 7;

  t->intensity = intensity;

  tm1638_send_config(t);
}

/**
 *
 * Send the settings in t to the actual hardware.
 *
 * @param t  Pointer to the tm1638 of interest.
 */
static void tm1638_send_config(const tm1638_p t)
{
  tm1638_send_command(t, tm1638_calc_config(t));
}

/**
 *
 * Given settings in t, calculate the config byte to send.
 *
 * @param t  Pointer to the tm1638 of interest.
 *
 * @return   The byte of config data we need to send.
 */
static uint8_t tm1638_calc_config(const tm1638_p t)
{
  return 0x80 | (t->enable ? 8 : 0) | t->intensity;
}

/**
 *
 * Low-level command primitive: send a byte to the hardware.
 *
 * @param t  Pointer to the tm1638 of interest.
 * @param x  The byte to send.
 */
static void tm1638_send_raw(const tm1638_p t, uint8_t x)
{
  /* The delays in this code are somewhat arbitrary: they work for me
     but I make no claims that they are optimal or robust */
  for(int i = 0; i < 8; i++)
    {
      bcm2835_gpio_write(t->clock, LOW);
      delayMicroseconds(1);

      bcm2835_gpio_write(t->data, x & 1 ? HIGH : LOW);
      delayMicroseconds(1);

      x  >>= 1;
      bcm2835_gpio_write(t->clock, HIGH);
      delayMicroseconds(1);
    }
}

/**
 *
 * Low-level command primitive: read a byte from the hardware.
 *
 * @param t  Pointer to the tm1638 of interest.
 *
 * @return   The byte we read.
 */
static uint8_t tm1638_receive_raw(const tm1638_p t)
{
  /* The delays in this code are somewhat arbitrary: they work for me
     but I make no claims that they are optimal or robust */

  uint8_t x = 0;

  /* Turn GPIO pin into an input */
  bcm2835_gpio_fsel(t->data, BCM2835_GPIO_FSEL_INPT);
    
  for(int i = 0; i < 8; i++)
    {
      x <<= 1;

      bcm2835_gpio_write(t->clock, LOW);
      delayMicroseconds(1);

      uint8_t y = bcm2835_gpio_lev(t->data);

      if (y & 1)
	x |= 1;
      delayMicroseconds(1);

      bcm2835_gpio_write(t->clock, HIGH);
      delayMicroseconds(1);
    }

  /* Turn GPIO pin back into an output */
  bcm2835_gpio_fsel(t->data, BCM2835_GPIO_FSEL_OUTP);

  return x;
}

/**
 *
 * Medium-level command primitive: send a command to the hardware.
 *
 * @param t  Pointer to the tm1638 of interest.
 * @param x  The command to send.
 */
static void tm1638_send_command(const tm1638_p t, uint8_t x)
{
  /* The delays in this code are somewhat arbitrary: they work for me
     but I make no claims that they are optimal or robust */
  bcm2835_gpio_write(t->strobe, LOW);
  delayMicroseconds(1);

  tm1638_send_raw(t, x);

  bcm2835_gpio_write(t->strobe, HIGH);
  delayMicroseconds(1);
}

/**
 *
 * Medium-level command primitive: write a data byte to the hardware.
 *
 * @param t    Pointer to the tm1638 of interest.
 * @param addr The address to write.
 * @param data The data to write.
 */
static void tm1638_send_data(const tm1638_p t, uint8_t addr, uint8_t data)
{
  /* The delays in this code are somewhat arbitrary: they work for me
     but I make no claims that they are optimal or robust */
  tm1638_send_command(t, 0x44);
  
  bcm2835_gpio_write(t->strobe, LOW);
  delayMicroseconds(1);

  tm1638_send_raw(t, 0xc0 | addr);
  tm1638_send_raw(t, data);

  bcm2835_gpio_write(t->strobe, HIGH);
  delayMicroseconds(1);
}
    
/* See tm1638.h */
void tm1638_set_7seg_raw(const tm1638_p t, uint8_t digit, uint8_t n)
{
  tm1638_send_data(t, digit << 1, n);
}

/* See tm1638.h */
void tm1638_set_7seg_text(const tm1638_p t, const char *str, uint8_t dots)
{
  const char *p = str;

  for(int i = 0, j = 1; i < 8; i++, j <<= 1)
    {
      // We want the loop to finish, but don't walk over the end of the string
      char c = *p;
      if (c)
	p++;
      
      uint8_t f =  tm1638_font(c);

      if (dots & j)
	f |= 128;

      tm1638_set_7seg_raw(t, i, f);
    }
}

/* See tm1638.h */
void tm1638_set_led(const tm1638_p t, uint8_t led, uint8_t cols)
{
  tm1638_send_data(t, (led << 1) + 1, cols);
}

/* See tm1638.h */
void tm1638_set_8leds(const tm1638_p t, uint8_t red, uint8_t green)
{
  for(int i = 0, j = 128; i < 8; i++, j >>= 1)
    tm1638_set_led(t, i, ((red & j) ? 1 : 0) + ((green & j) ? 2 : 0));
}

/* See tm1638.h */
void tm1638_send_cls(const tm1638_p t)
{
  /* The delays in this code are somewhat arbitrary: they work for me
     but I make no claims that they are optimal or robust */
  tm1638_send_command(t, 0x40);

  bcm2835_gpio_write(t->strobe, LOW);
  delayMicroseconds(1);
  
  tm1638_send_raw(t, 0xc0);
  for(int i = 0; i < 16; i++)
    tm1638_send_raw(t, 0x00);

  bcm2835_gpio_write(t->strobe, HIGH);
  delayMicroseconds(1); 
}

/* See tm1638.h */
uint8_t tm1638_font(char c)
{
  const uint8_t f[] = {
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
    0x00, 0x86, 0x22, 0x7e,  0x6d, 0x00, 0x00, 0x02,
    0x30, 0x06, 0x63, 0x00,  0x04, 0x40, 0x80, 0x52,
    0x3f, 0x06, 0x5b, 0x4f,  0x66, 0x6d, 0x7d, 0x27,
    0x7f, 0x6f, 0x00, 0x00,  0x00, 0x48, 0x00, 0x53,
    0x5f, 0x77, 0x7f, 0x39,  0x3f, 0x79, 0x71, 0x3d,
    0x76, 0x06, 0x1f, 0x69,  0x38, 0x15, 0x37, 0x3f,
    0x73, 0x67, 0x31, 0x6d,  0x78, 0x3e, 0x2a, 0x1d,
    0x76, 0x6e, 0x5b, 0x39,  0x64, 0x0f, 0x00, 0x08,
    0x20, 0x5f, 0x7c, 0x58,  0x5e, 0x7b, 0x31, 0x6f,
    0x74, 0x04, 0x0e, 0x75,  0x30, 0x55, 0x54, 0x5c,
    0x73, 0x67, 0x50, 0x6d,  0x78, 0x1c, 0x2a, 0x1d,
    0x76, 0x6e, 0x47, 0x46,  0x06, 0x70, 0x01, 0x00
  };

  return (c > 127) ? 0 : f[(unsigned char)c];
}

/* See tm1638.h */
uint32_t tm1638_read_buttons(const tm1638_p t)
{
  /* The delays in this code are somewhat arbitrary: they work for me
     but I make no claims that they are optimal or robust */
  bcm2835_gpio_write(t->strobe, LOW);
  delayMicroseconds(1);

  tm1638_send_raw(t, 0x42);
  
  uint32_t x = 0;
  for(int i = 0; i < 4; i++)
    {
      x <<= 8;
      x |= tm1638_receive_raw(t);
    }

  bcm2835_gpio_write(t->strobe, HIGH);
  delayMicroseconds(1);

  return x;
}

/* See tm1638.h */
uint8_t tm1638_read_8buttons(const tm1638_p t)
{
  uint32_t x = tm1638_read_buttons(t);
  uint8_t  y = 0;
  
  for(int i = 0; i < 4; i++)
    {
      y <<= 1;

      if (x & 0x80000000)
	y |= 0x10;

      if (x & 0x08000000)
	y |= 0x01;

      x <<= 8;
    }

  return y;
}
  
