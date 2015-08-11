#include "utils.h"

static unsigned char access_buf[0x140];

static void BuildTable32( unsigned long aPoly , unsigned long* Table_CRC )
{
    unsigned long i, j;
    unsigned long nData;
    unsigned long nAccum;
	
    for ( i = 0; i < 256; i++ )
    {
        nData = ( unsigned long )( i << 24 );
        nAccum = 0;
        for ( j = 0; j < 8; j++ )
        {
            if ( ( nData ^ nAccum ) & 0x80000000 )
                nAccum = ( nAccum << 1 ) ^ aPoly;
            else
                nAccum <<= 1;
            nData <<= 1;
        }
        Table_CRC[i] = nAccum;
    }
}


static int
access_open(CrackContext *ctx)
{
	int ret;
	FILE *fp;
	
	//
	// ¶ÁaccessÎÄ¼þ
	//
	
	fp = fopen(ctx->input_filename, "rb");
	if (NULL == fp)
	{
		return -1;
	}
	
	ret = fread(access_buf, 1, 0x140, fp);
    fclose(fp);
	
	if (strcmp(&access_buf[4], "Standard Jet DB") != 0)
    {
		return -1;
	}

	return 0;
}

void LoGetEncryptStr(unsigned char *fbytEncriptKey, unsigned char *fbytEncriptRet, long flModeValue)
{
	int i, l;
	long lTemp1 = 0, lTemp2 = 0, lTemp3 = 0, lTemp4 = 0, lTemp5 = 0;
	
	for (i=0; i<256; i++)
	{
		fbytEncriptRet[i] = i;
	}
	
	lTemp1 = 0;
	for(l=0; l<256; l++)
	{
		lTemp1 = lTemp2;
		lTemp1 = fbytEncriptKey[lTemp1];
		lTemp4 = fbytEncriptRet[l];
		lTemp1 = lTemp1 + lTemp4;
		lTemp4 = lTemp3;
		lTemp1 = lTemp1 + lTemp4;
		lTemp1 = lTemp1 & 0x800000FF;
		lTemp3 = lTemp1;
		lTemp1 = fbytEncriptRet[l];
		lTemp5 = lTemp1;
		lTemp1 = lTemp3;
		lTemp1 = fbytEncriptRet[lTemp1];
		fbytEncriptRet[l] = (u8)lTemp1;
		lTemp4 = lTemp3;
		fbytEncriptRet[lTemp4] = (u8)lTemp5;
		lTemp1 = lTemp2;
		lTemp1 = lTemp1 + 1;
		lTemp4 = lTemp1 % flModeValue;
		lTemp2 = lTemp4;
	}
}

void LoGetKey(unsigned char *fbytEncriptKey, unsigned char *fbytKeyRet, long flMaxValue)
{
	int l = 0;
	long lTemp1 = 0, lTemp2 = 0, lTemp3 = 0, lTemp4 = 0, lTemp5 = 0, lTemp6 = 0, lTemp7 = 0, lTemp8 = 0;
	lTemp4 = fbytEncriptKey[0x100];
	lTemp1 = fbytEncriptKey[0x101];
	
	for (l=1; l<=flMaxValue; l++)
	{
		lTemp4 = lTemp4 + 1;
		lTemp4 = lTemp4 & 0x800000FF;
		lTemp3 = lTemp4 & 0xFF;
		lTemp5 = fbytEncriptKey[lTemp3];
		lTemp1 = lTemp1 & 0xFF;
		lTemp5 = lTemp5 + lTemp1;
		lTemp1 = lTemp5 & 0x800000FF;
		lTemp6 = fbytEncriptKey[lTemp4];
		lTemp5 = fbytEncriptKey[lTemp1];
		fbytEncriptKey[lTemp3] = (u8)lTemp5;
		lTemp2 = lTemp1;
		fbytEncriptKey[lTemp2] = (u8)lTemp6;
		lTemp5 = fbytEncriptKey[lTemp3];
		lTemp3 = fbytEncriptKey[lTemp1 & 0xFF];
		lTemp5 = lTemp5 + lTemp3;
		lTemp5 = lTemp5 & 0x800000FF;
		lTemp7 = lTemp5;
		lTemp3 = lTemp8;
		lTemp5 = fbytEncriptKey[lTemp5];
		fbytKeyRet[lTemp3] = fbytKeyRet[lTemp3] ^ (u8)lTemp5;
		lTemp8 = lTemp8 + 1;
	}
	fbytEncriptKey[0x100] = (u8)lTemp4;
	fbytEncriptKey[0x101] = (u8)lTemp1;
}

static int
access_crack(CrackContext *ctx, char *string, unsigned int len)
{
	unsigned char bytEncriptKey[4] = {0};
	unsigned char bytEncriptRet[258] = {0};
	unsigned char *fbytFile = access_buf + 0x18;
	double dbl = 0.0;
	unsigned short lKey = 0;
	unsigned short lRslt[20] = {0};
	int l = 0;
	
	bytEncriptKey[0] = 0xC7;
	bytEncriptKey[1] = 0xDA;
	bytEncriptKey[2] = 0x39;
	bytEncriptKey[3] = 0x6B;
	
	LoGetEncryptStr(bytEncriptKey, bytEncriptRet, 4);
	LoGetKey(bytEncriptRet, fbytFile, 0x80);
	memcpy(&dbl, fbytFile + 90, 8);
	lKey = (unsigned short)dbl;
	for (l=0; l<20; l++)
	{
		lRslt[l] = *((unsigned short *)(fbytFile + l*2 + 42));
		if (0 == l % 2)
		{
			lRslt[l] = lRslt[l] ^ lKey;
		}	
		ctx->pw[l] = (char)lRslt[l];
	}
	
	return 1;
}

static int
access_close(CrackContext *ctx)
{
	return 0;
}

Cracker access_cracker = 
{
	"matrix access cracker", 
	"mdb", 
	CRACK_TYPE_DIRECT, 
    CRACK_ID_ACCESS, 
	0, 
	access_open, 
	access_crack, 
	access_close, 
	NULL
};
