#include <stdio.h>
#include <stdint.h>

uint32_t my_ntohl(uint32_t n)
{
        uint32_t n1 = n & 0xFF000000;
        uint32_t n2 = n & 0x00FF0000;
        uint32_t n3 = n & 0x0000FF00;
        uint32_t n4 = n & 0x000000FF;

        uint32_t ret = (n1 >> 24) | (n2 >> 8) | (n3 << 8) | (n4 << 24);
        return ret;
}

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
	
	num1 = my_ntohl(raw1);
	num2 = my_ntohl(raw2);

	sum = num1 + num2;

	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", num1, num1, num2, num2, sum, sum);
}
