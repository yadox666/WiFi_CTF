#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <bcm2835.h>
#include <tm1638.h>

int main(int argc, char *argv[]) {
    int n,i;
    if( argc > 3 ) {
        printf("Too many arguments supplied.\n");
	return(1);
    }
    else if( argc == 3 ) {
	n = strtol(argv[2], NULL, 0);
    }
    else if( argc == 2 ) {
	n=1;
    }
    else {
        printf("At least one argument expected (blink times)\n");
	return(1);
    }
    i=0;
    bcm2835_init();
    tm1638_p t = tm1638_alloc(17, 27, 22);
    while(i<n) {
        tm1638_set_7seg_text(t,"        ", 0x00);
        delay(200);
        tm1638_set_7seg_text(t, argv[1], 0x00);
        delay(200);
	i++;
    }
    return 0;
}
