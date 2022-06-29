#include<stdio.h>
#include<stdint.h>
#include<netinet/in.h>


int main(int argc, char* argv[]) {
	uint32_t argv_1;
	uint32_t argv_2;

	FILE* f1 = fopen(argv[1], "r");
	FILE* f2 = fopen(argv[2], "r");

	fread(&argv_1, sizeof(argv_1), 1, f1);
	fread(&argv_2, sizeof(argv_2), 1, f2);

	argv_1 = ntohl(argv_1);
	argv_2 = ntohl(argv_2);

	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)", argv_1, argv_1, 
						argv_2, argv_2,
					       	argv_1 + argv_2, argv_1 + argv_2);

}
