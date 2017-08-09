#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <bcm2835.h>
#include <tm1638.h>

int main(int argc, char *argv[])
{
    bcm2835_init();
    tm1638_p t = tm1638_alloc(17, 27, 22);
    while(t)
        {
	    time_t now = time(NULL);
	    struct tm *tm = localtime(&now);
	    char text[10];
	    snprintf(text, 9, "%02d-%02d-%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
	    tm1638_set_7seg_text(t, text, 0x00);
	    delay(100);
        }
    return 0;
}
