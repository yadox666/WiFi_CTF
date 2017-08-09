#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <bcm2835.h>
#include <tm1638.h>

struct TIME
{
  int seconds;
  int minutes;
  int hours;
};

void differenceBetweenTimePeriod(struct TIME t1, struct TIME t2, struct TIME *diff);

int main(int argc, char *argv[]) {
    int timeout;
    if( argc > 2 ) {
        printf("Too many arguments supplied.\nJust supply countdown timer seconds!\n");
        return(1);
    }
    else if( argc == 2 ) {
        timeout = strtol(argv[1], NULL, 0);
    }
    else {
        printf("At least one argument expected.\nJust supply countdown timer seconds!\n");
        return(1);
    }

    bcm2835_init();
    tm1638_p t = tm1638_alloc(17, 27, 22);

    struct TIME startTime, timeNow, diff;
    time_t now = time(NULL)+timeout; // sum input time in seconds to now
    struct tm *tm = localtime(&now);
    startTime.hours=tm->tm_hour;
    startTime.minutes=tm->tm_min;
    startTime.seconds=tm->tm_sec;

    while(t) {
	    time_t now = time(NULL);
	    struct tm *tm = localtime(&now);
            timeNow.hours=tm->tm_hour;
	    timeNow.minutes=tm->tm_min;
	    timeNow.seconds=tm->tm_sec;

            // Calculate the difference between the start and stop time period.
            differenceBetweenTimePeriod(startTime, timeNow, &diff);
	    if (diff.hours + diff.minutes + diff.seconds > 0) {
	       char text[10];
	       snprintf(text, 9, "%02d-%02d-%02d", diff.hours, diff.minutes, diff.seconds);
	       tm1638_set_7seg_text(t, text, 0x00);
	       delay(1000);
           }
           else {
	       tm1638_set_7seg_text(t, "00-00-00", 0x00);
               for (int j = 0; j < 5; j++){
	           delay(300);
	           tm1638_set_7seg_text(t, "", 0x00);
	           delay(300);
	           tm1638_set_7seg_text(t, "--------", 0x00);
               }
               return(2);
           }
        }
    return 0;
}

void differenceBetweenTimePeriod(struct TIME start, struct TIME stop, struct TIME *diff)
{
    if(stop.seconds > start.seconds){
        --start.minutes;
        start.seconds += 60;
    }

    diff->seconds = start.seconds - stop.seconds;
    if(stop.minutes > start.minutes){
        --start.hours;
        start.minutes += 60;
    }

    diff->minutes = start.minutes - stop.minutes;
    diff->hours = start.hours - stop.hours;
}
