#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
	if(argc != 3)
	{
		printf("usage : %s <file1> <file2>\n", argv[0]);
		return 0;
	}

	uint32_t raw1 = 0;
	uint32_t raw2 = 0;
	uint32_t num1 = 0;
	uint32_t num2 = 0;
	uint32_t sum = 0;
	FILE *fp1;
	FILE *fp2;
	fp1 = fopen(argv[1], "r");
	if(!fp1)
	{
		printf("Failed to open file : %s\n", argv[1]);
		return 0;
	}
	
	fp2 = fopen(argv[2], "r");
	if(!fp2)
	{
		printf("Filaed to open file : %s\n", argv[2]);
		return 0;
	}

	fread(&raw1, 4, 1, fp1);
	fread(&raw2, 4, 1, fp2);
	
	num1 = ntohl(raw1);
	num2 = ntohl(raw2);

	sum = num1 + num2;

	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", num1, num1, num2, num2, sum, sum);
}
