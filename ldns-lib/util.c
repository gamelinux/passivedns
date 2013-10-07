/*
 * util.c
 *
 * some general memory functions
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2006
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/rdata.h>
#include <ldns/rr.h>
#include <ldns/util.h>
#ifdef _MSC_VER
#include <string.h>
#include <compat/gettimeofday.h>
#else
#include <strings.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#ifndef _MSC_VER
#include <sys/time.h>
#endif
#include <time.h>

#ifdef HAVE_SSL
#include <openssl/rand.h>
#endif

/* put this here tmp. for debugging */
void
xprintf_rdf(ldns_rdf *rd)
{
	/* assume printable string */
	fprintf(stderr, "size\t:%u\n", (unsigned int)ldns_rdf_size(rd));
	fprintf(stderr, "type\t:%u\n", (unsigned int)ldns_rdf_get_type(rd));
	fprintf(stderr, "data\t:[%.*s]\n", (int)ldns_rdf_size(rd), 
			(char*)ldns_rdf_data(rd));
}

void
xprintf_rr(ldns_rr *rr)
{
	/* assume printable string */
	uint16_t count, i;

	count = ldns_rr_rd_count(rr);

	for(i = 0; i < count; i++) {
		fprintf(stderr, "print rd %u\n", (unsigned int) i);
		xprintf_rdf(rr->_rdata_fields[i]);
	}
}

void xprintf_hex(uint8_t *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (i > 0 && i % 20 == 0) {
			printf("\t; %u - %u\n", (unsigned int) i - 19, (unsigned int) i);
		}
		printf("%02x ", (unsigned int) data[i]);
	}
	printf("\n");
}

ldns_lookup_table *
ldns_lookup_by_name(ldns_lookup_table *table, const char *name)
{
	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0)
			return table;
		table++;
	}
	return NULL;
}

ldns_lookup_table *
ldns_lookup_by_id(ldns_lookup_table *table, int id)
{
	while (table->name != NULL) {
		if (table->id == id)
			return table;
		table++;
	}
	return NULL;
}

int 
ldns_get_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	return (int) (bits[index / 8] & (1 << (7 - index % 8)));
}

int 
ldns_get_bit_r(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from right to left, so bit #0 is the
	 * right most bit.
	 */
	return (int) bits[index / 8] & (1 << (index % 8));
}

void
ldns_set_bit(uint8_t *byte, int bit_nr, bool value) 
{
	if (bit_nr >= 0 && bit_nr < 8) {
		if (value) {
			*byte = *byte | (0x01 << bit_nr);
		} else {
			*byte = *byte & !(0x01 << bit_nr);
		}
	}
}

int
ldns_hexdigit_to_int(char ch)
{
	switch (ch) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': case 'A': return 10;
	case 'b': case 'B': return 11;
	case 'c': case 'C': return 12;
	case 'd': case 'D': return 13;
	case 'e': case 'E': return 14;
	case 'f': case 'F': return 15;
	default:
		return -1;
	}
}

char 
ldns_int_to_hexdigit(int i)
{
	switch (i) {
	case 0: return '0';
	case 1: return '1';
	case 2: return '2';
	case 3: return '3';
	case 4: return '4';
	case 5: return '5';
	case 6: return '6';
	case 7: return '7';
	case 8: return '8';
	case 9: return '9';
	case 10: return 'a';
	case 11: return 'b';
	case 12: return 'c';
	case 13: return 'd';
	case 14: return 'e';
	case 15: return 'f';
	default:
		abort();
	}
	return '0';	//just to avoid compiler warning
}

int
ldns_hexstring_to_data(uint8_t *data, const char *str)
{
	size_t i;

	if (!str || !data) {
		return -1;
	}

	if (strlen(str) % 2 != 0) {
		return -2;
	}

	for (i = 0; i < strlen(str) / 2; i++) {
		data[i] = 
			16 * (uint8_t) ldns_hexdigit_to_int(str[i*2]) +
			(uint8_t) ldns_hexdigit_to_int(str[i*2 + 1]);
	}

	return (int) i;
}

const char *
ldns_version(void)
{
	return (char*)LDNS_VERSION;
}

/* Number of days per month (except for February in leap years). */
static const int mdays[] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static int 
is_leap_year(int year)
{
	return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int
leap_days(int y1, int y2)
{
	--y1;
	--y2;
	return (y2/4 - y1/4) - (y2/100 - y1/100) + (y2/400 - y1/400);
}

/*
 * Code adapted from Python 2.4.1 sources (Lib/calendar.py).
 */
time_t
mktime_from_utc(const struct tm *tm)
{
	int year = 1900 + tm->tm_year;
	time_t days = 365 * ((time_t) year - 1970) + leap_days(1970, year);
	time_t hours;
	time_t minutes;
	time_t seconds;
	int i;

	for (i = 0; i < tm->tm_mon; ++i) {
		days += mdays[i];
	}
	if (tm->tm_mon > 1 && is_leap_year(year)) {
		++days;
	}
	days += tm->tm_mday - 1;

	hours = days * 24 + tm->tm_hour;
	minutes = hours * 60 + tm->tm_min;
	seconds = minutes * 60 + tm->tm_sec;

	return seconds;
}

/**
 * Init the random source
 * applications should call this if they need entropy data within ldns
 * If openSSL is available, it is automatically seeded from /dev/urandom
 * or /dev/random
 *
 * If you need more entropy, or have no openssl available, this function
 * MUST be called at the start of the program
 *
 * If openssl *is* available, this function just adds more entropy
 **/
int
ldns_init_random(FILE *fd, unsigned int size) 
{
	/* if fp is given, seed srandom with data from file
	   otherwise use /dev/urandom */
	FILE *rand_f;
	uint8_t *seed;
	size_t read = 0;
	unsigned int seed_i;
	struct timeval tv;
	struct timezone tz;

	/* we'll need at least sizeof(unsigned int) bytes for the
	   standard prng seed */
	if (size < (unsigned int) sizeof(seed_i)){
		size = (unsigned int) sizeof(seed_i);
	}
	
	seed = LDNS_XMALLOC(uint8_t, size);

	if (!fd) {
		if ((rand_f = fopen("/dev/urandom", "r")) == NULL) {
			/* no readable /dev/urandom, try /dev/random */
			if ((rand_f = fopen("/dev/random", "r")) == NULL) {
				/* no readable /dev/random either, and no entropy
				   source given. we'll have to improvise */
				for (read = 0; read < size; read++) {
					gettimeofday(&tv, &tz);
					seed[read] = (uint8_t) (tv.tv_usec % 256);
				}
			} else {
				read = fread(seed, 1, size, rand_f);
			}
		} else {
			read = fread(seed, 1, size, rand_f);
		}
	} else {
		rand_f = fd;
		read = fread(seed, 1, size, rand_f);
	}
	
	if (read < size) {
		LDNS_FREE(seed);
		return 1;
	} else {
#ifdef HAVE_SSL
		/* Seed the OpenSSL prng (most systems have it seeded
		   automatically, in that case this call just adds entropy */
		RAND_seed(seed, (int) size);
#else
		/* Seed the standard prng, only uses the first
		 * unsigned sizeof(unsiged int) bytes found in the entropy pool
		 */
		memcpy(&seed_i, seed, sizeof(seed_i));
		srandom(seed_i);
#endif
		LDNS_FREE(seed);
	}
	
	if (rand_f) {
		fclose(rand_f);
	}

	return 0;
}

/*
 * BubbleBabble code taken from OpenSSH
 * Copyright (c) 2001 Carsten Raskgaard.  All rights reserved.
 */
char *
ldns_bubblebabble(uint8_t *data, size_t len)
{
	char vowels[] = { 'a', 'e', 'i', 'o', 'u', 'y' };
	char consonants[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'k', 'l', 'm',
	    'n', 'p', 'r', 's', 't', 'v', 'z', 'x' };
	size_t i, j = 0, rounds, seed = 1;
	char *retval;

	rounds = (len / 2) + 1;
	retval = LDNS_XMALLOC(char, rounds * 6);
	retval[j++] = 'x';
	for (i = 0; i < rounds; i++) {
		size_t idx0, idx1, idx2, idx3, idx4;
		if ((i + 1 < rounds) || (len % 2 != 0)) {
			idx0 = (((((size_t)(data[2 * i])) >> 6) & 3) +
			    seed) % 6;
			idx1 = (((size_t)(data[2 * i])) >> 2) & 15;
			idx2 = ((((size_t)(data[2 * i])) & 3) +
			    (seed / 6)) % 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
			if ((i + 1) < rounds) {
				idx3 = (((size_t)(data[(2 * i) + 1])) >> 4) & 15;
				idx4 = (((size_t)(data[(2 * i) + 1]))) & 15;
				retval[j++] = consonants[idx3];
				retval[j++] = '-';
				retval[j++] = consonants[idx4];
				seed = ((seed * 5) +
				    ((((size_t)(data[2 * i])) * 7) +
				    ((size_t)(data[(2 * i) + 1])))) % 36;
			}
		} else {
			idx0 = seed % 6;
			idx1 = 16;
			idx2 = seed / 6;
			retval[j++] = vowels[idx0];
			retval[j++] = consonants[idx1];
			retval[j++] = vowels[idx2];
		}
	}
	retval[j++] = 'x';
	retval[j++] = '\0';
	return retval;
}
