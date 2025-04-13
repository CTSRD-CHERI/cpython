#include <stdio.h>
#include <math.h>

int main(void) {
	double x = 1.0;
	double y = acosh(x);
	printf("acosh(%f) = %f\n", x, y);
	return 0;
}

