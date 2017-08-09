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
 * @section EXAMPLE
 *
 *     #include <bcm2835.h>
 *     #include <tm1638.h>
 *     
 *     ...
 *     
 *     if (!bcm2835_init())
 *       { ... }
 *     
 *     tm1638_p t = tm1638_alloc(17, 21, 22);
 *     if (!t)
 *       { ... }
 *     
 *     tm1638_set_7seg_text(t, "Hello!", 0xc0);
 *
 *     while(...)
 *       {
 *         uint8_t  x = tm1638_read_8buttons(t);
 *         tm1638_set_8leds(t, 0, x);
 *       }
 *     
 *     tm1638_free(&t);
 *
 * @section DEPENDENCIES
 *
 * All of the hardware interfacing is done via Mike McCauley's
 * excellent bcm2835 library, so you'll need to install that
 * first. Get it from http://www.open.com.au/mikem/bcm2835/
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

#ifndef _TM1638_H_
#define _TM1638_H_

/**
   Forward declaration of the tm1638 structure. Users of the library
   should treat this as an opaque object and all interaction with the
   struct will be indirect.

   That is, the library will allocate and free all the structs, so
   your code should only contain pointers to tm1638 structs, not the structs themselves.
*/
typedef struct tm1638_tag tm1638;

/**
   With this in mind, here's a pointer!
*/
typedef tm1638 *tm1638_p;

/**
 * Allocation and initialization function, aka constructor.
 *
 * NOTES:
 * 1. You must initialize the bcm2825 library first!
 * 2. You must pair every tm1638_alloc with a tm1638_free!
 *
 * All the parameters specify the pins we've connected to the TM1638 board:
 *
 * @param data   Pin used for data.
 * @param clock  Pin used for clock.
 * @param strobe Pin used for strobe.
 *
 * @return       Pointer to tm1638 struct, or NULL if failure!
 */
tm1638_p tm1638_alloc(uint8_t data, uint8_t clock, uint8_t strobe);

/**
 * Freeing function aka destructor.
 *
 * @param t      Pointer to tm1638 pointer, set to NULL when freed.
 */
void     tm1638_free(tm1638_p *t);

/**
 *
 * Enable/disable the display
 *
 * @param t       Pointer to the tm1638 of interest.
 * @param enable  Enable (true) or disable (false).
 */
void tm1638_enable(tm1638_p t, bool enable);

/**
 *
 * Set the display intensity.
 *
 * @param t           Pointer to the tm1638 of interest.
 * @param intensity   The desired intensity (0-7).
 */
void tm1638_set_intensity(tm1638_p t, uint8_t intensity);

/**
 *
 * Set segments in a particular digit.
 *
 * @param t       Pointer to the tm1638 of interest.
 * @param digit   The digit of interest (0 is left-most).
 * @param n       The segments to set: (1 is top central, 128 is the point).
 */
void tm1638_set_7seg_raw(const tm1638_p t, uint8_t digit, uint8_t n);

/**
 *
 * Display some text on the display.
 *
 * @param t       Pointer to the tm1638 of interest.
 * @param str     The text to display.
 * @param dots    The 8 bits correspond to the decimal points, LSB = leftmost.
 */
void tm1638_set_7seg_text(const tm1638_p t, const char *str, uint8_t dots);

/**
 *
 * Set the status of one LED
 *
 * @param t       Pointer to the tm1638 of interest.
 * @param led     The LED in question.
 * @param cols    The colour to which it should be set.
 */
void tm1638_set_led(const tm1638_p t, uint8_t led, uint8_t cols);

/**
 *
 * Set the status of all eight LEDs at once
 *
 * @param t       Pointer to the tm1638 of interest.
 * @param red     A byte's worth of red data (MSB is leftmost).
 * @param green   A byte's worth of green data (MSB is leftmost).
 *
 * The ordering might seem odd, but makes the display a sensible
 * binary rendition of red & green.
 */
void tm1638_set_8leds(const tm1638_p t, uint8_t red, uint8_t green);

/**
 *
 * Turn off all the LEDs
 *
 * @param t       Pointer to the tm1638 of interest.
 */
void tm1638_send_cls(const tm1638_p t);

/**
 *
 * A simple 7-segment font.
 *
 * @param c       The ASCII character of interest.
 *
 * @return        The segments to set.
 */
uint8_t tm1638_font(char c);

/**
 *
 * Read the 32-bit button input register. 
 * The bit order in here isn't helpful for the standard
 * boards with eight buttons on them: see tm1638_read_8buttons()
 * instead.
 *
 * @param t       Pointer to the tm1638 of interest.
 *
 * @return        32-bit uint of button states.
 */
uint32_t tm1638_read_buttons(const tm1638_p t);

/**
 *
 * Read the state of the eight buttons on the standard board.
 *
 * @param t       Pointer to the tm1638 of interest.
 *
 * @return        8-bit uint of button states. MSB is leftmost.
 */
uint8_t  tm1638_read_8buttons(const tm1638_p t);

#endif
