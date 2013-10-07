/*
 * a generic (simple) parser. Use to parse rr's, private key 
 * information and /etc/resolv.conf files
 *
 * a Net::DNS like library for C
 * LibDNS Team @ NLnet Labs
 * (c) NLnet Labs, 2005-2006
 * See the file LICENSE for the license
 */
#include <ldns/config.h>
#include <ldns/ldns.h>

#include <limits.h>
#ifdef _MSC_VER
#include <string.h>
#else
#include <strings.h>
#endif

ldns_lookup_table ldns_directive_types[] = {
        { LDNS_DIR_TTL, "$TTL" },  
        { LDNS_DIR_ORIGIN, "$ORIGIN" }, 
        { LDNS_DIR_INCLUDE, "$INCLUDE" },  
        { 0, NULL }
};

/* add max_limit here? */
ssize_t
ldns_fget_token(FILE *f, char *token, const char *delim, size_t limit)
{	
	return ldns_fget_token_l(f, token, delim, limit, NULL);
}

ssize_t
ldns_fget_token_l(FILE *f, char *token, const char *delim, size_t limit, int *line_nr)
{	
	int c, prev_c;
	int p; /* 0 -> no parenthese seen, >0 nr of ( seen */
	int com, quoted;
	char *t;
	size_t i;
	const char *d;
	const char *del;

	/* standard delimeters */
	if (!delim) {
		/* from isspace(3) */
		del = LDNS_PARSE_NORMAL;
	} else {
		del = delim;
	}

	p = 0;
	i = 0;
	com = 0;
	quoted = 0;
	prev_c = 0;
	t = token;
	if (del[0] == '"') {
		quoted = 1;
	}
	while ((c = getc(f)) != EOF) {
		if (c == '(' && prev_c != '\\') {
			/* this only counts for non-comments */
			if (com == 0) {
				p++;
			}
			prev_c = c;
			continue;
		}

		if (c == ')' && prev_c != '\\') {
			/* this only counts for non-comments */
			if (com == 0) {
				p--;
			}
			prev_c = c;
			continue;
		}

		if (p < 0) {
			/* more ) then ( - close off the string */
			*t = '\0';
			return 0;
		}

		/* do something with comments ; */
		if (c == ';' && quoted == 0) {
			if (prev_c == '\\') {
				*t++ = 'a';
			} else {
				com = 1;
			}
		}
		if (c == '\"' && com == 0 && prev_c != '\\') {
			quoted = 1 - quoted;
		}

		if (c == '\n' && com != 0) {
			/* comments */
			com = 0;
			*t = ' ';
			if (line_nr) {
				*line_nr = *line_nr + 1;
			}
			if (p == 0 && i > 0) {
				goto tokenread;
			} else {
				prev_c = c;
				continue;
			}
		}

		if (com == 1) {
			*t = ' ';
			prev_c = c;
			continue;
		}

		
		if (c == '\n' && p != 0 && t > token) {
			/* in parentheses */
			if (line_nr) {
				*line_nr = *line_nr + 1;
			}
			prev_c = c;
			continue;
		}

		/* check if we hit the delim */
		for (d = del; *d; d++) {
			if (c == *d && i > 0) {
				if (c == '\n' && line_nr) {
					*line_nr = *line_nr + 1;
				}
				goto tokenread;
			}
		}
		if (c != '\0' && c != '\n') {
			*t++ = c;
			i++;
		}
		if (limit > 0 && i >= limit) {
			*t = '\0';
			return -1;
		}
		prev_c = c;
	}
	*t = '\0';
	if (c == EOF) {
		return (ssize_t)i;
	}

	if (i == 0) {
		/* nothing read */
		return -1;
	}
	if (p != 0) {
		return -1;
	}
	return (ssize_t)i;

tokenread:
	ldns_fskipcs_l(f, delim, line_nr);
	*t = '\0';
	if (p != 0) {
		return -1;
	}

	return (ssize_t)i;
}

ssize_t
ldns_fget_keyword_data(FILE *f, const char *keyword, const char *k_del, char *data,
               const char *d_del, size_t data_limit)
{
       return ldns_fget_keyword_data_l(f, keyword, k_del, data, d_del, 
		       data_limit, NULL);
}

ssize_t
ldns_fget_keyword_data_l(FILE *f, const char *keyword, const char *k_del, char *data,
               const char *d_del, size_t data_limit, int *line_nr)
{
       /* we assume: keyword|sep|data */
       char *fkeyword;
       ssize_t i;

       fkeyword = LDNS_XMALLOC(char, LDNS_MAX_KEYWORDLEN);
       i = 0;

       i = ldns_fget_token(f, fkeyword, k_del, LDNS_MAX_KEYWORDLEN);

       /* case??? i instead of strlen? */
       if (strncmp(fkeyword, keyword, LDNS_MAX_KEYWORDLEN - 1) == 0) {
               /* whee! */
               /* printf("%s\n%s\n", "Matching keyword", fkeyword); */
               i = ldns_fget_token_l(f, data, d_del, data_limit, line_nr);
               LDNS_FREE(fkeyword);
               return i;
       } else {
               /*printf("no match for %s (read: %s)\n", keyword, fkeyword);*/
               LDNS_FREE(fkeyword);
               return -1;
       }
}


ssize_t
ldns_bget_token(ldns_buffer *b, char *token, const char *delim, size_t limit)
{	
	int c, lc;
	int p; /* 0 -> no parenthese seen, >0 nr of ( seen */
	int com, quoted;
	char *t;
	size_t i;
	const char *d;
	const char *del;

	/* standard delimiters */
	if (!delim) {
		/* from isspace(3) */
		del = LDNS_PARSE_NORMAL;
	} else {
		del = delim;
	}

	p = 0;
	i = 0;
	com = 0;
	quoted = 0;
	t = token;
	lc = 0;
	if (delim[0] == '"') {
		quoted = 1;
	}

	while ((c = ldns_bgetc(b)) != EOF) {
		if (c == '(') {
			p++;
			lc = c;
			continue;
		}

		if (c == ')') {
			p--;
			lc = c;
			continue;
		}

		if (p < 0) {
			/* more ) then ( */
			*t = '\0';
			lc = c;
			return 0;
		}

		/* do something with comments ; */
		if (c == ';' && quoted == 0) {
			if (lc != '\\') {
				com = 1;
			} else {
				*t++ = '\\';
			}
		}
		if (c == '"' && com == 0 && lc != '\\') {
			quoted = 1 - quoted;
		}

		if (c == '\n' && com != 0) {
			/* comments */
			com = 0;
			*t = ' ';
			lc = c;
			continue;
		}

		if (com == 1) {
			*t = ' ';
			lc = c;
			continue;
		}

		if (c == '\n' && p != 0) {
			/* in parentheses */
			lc = c;
			continue;
		}

		/* check if we hit the delim */
		for (d = del; *d; d++) {
                        if (c == *d && lc != '\\') {
				goto tokenread;
                        }
		}
		
		*t++ = c;
		i++;
		if (limit > 0 && i >= limit - 1) {
			*t = '\0';
			return -1;
		}

		if (c == '\\' && lc == '\\') {
			lc = 0;
		} else {
			lc = c;
		}
	}
	*t = '\0';
	if (i == 0) {
		/* nothing read */
		return -1;
	}
	if (p != 0) {
		return -1;
	}
	return (ssize_t)i;

tokenread:
	ldns_bskipcs(b, delim);
	*t = '\0';
	
	if (p != 0) {
		return -1; 
	}
	return (ssize_t)i;
}

void
ldns_bskipc(ldns_buffer *buffer, char c)
{
        while (c == (char) ldns_buffer_read_u8_at(buffer, ldns_buffer_position(buffer))) {
                if (ldns_buffer_available_at(buffer, 
					buffer->_position + sizeof(char), sizeof(char))) {
                        buffer->_position += sizeof(char);
                } else {
                        return;
                }
        }
}

void
ldns_bskipcs(ldns_buffer *buffer, const char *s)
{
        bool found;
        char c;
        const char *d;

        while(ldns_buffer_available_at(buffer, buffer->_position, sizeof(char))) {
                c = (char) ldns_buffer_read_u8_at(buffer, buffer->_position);
                found = false;
                for (d = s; *d; d++) {
                        if (*d == c) {
                                found = true;
                        }
                }
                if (found && buffer->_limit > buffer->_position) {
                        buffer->_position += sizeof(char);
                } else {
                        return;
                }
        }
}

void
ldns_fskipc(FILE *fp, char c)
{
	fp = fp;
	c = c;
}


void
ldns_fskipcs(FILE *fp, const char *s)
{
	ldns_fskipcs_l(fp, s, NULL);
}

void
ldns_fskipcs_l(FILE *fp, const char *s, int *line_nr)
{
        bool found;
        int c;
        const char *d;

	while ((c = fgetc(fp)) != EOF) {
		if (line_nr && c == '\n') {
			*line_nr = *line_nr + 1;
		}
                found = false;
                for (d = s; *d; d++) {
                        if (*d == c) {
                                found = true;
                        }
                }
		if (!found) {
			/* with getc, we've read too far */
			ungetc(c, fp);
			return;
		}
	}
}

ssize_t
ldns_bget_keyword_data(ldns_buffer *b, const char *keyword, const char *k_del, char
*data, const char *d_del, size_t data_limit)
{
       /* we assume: keyword|sep|data */
       char *fkeyword;
       ssize_t i;

       fkeyword = LDNS_XMALLOC(char, LDNS_MAX_KEYWORDLEN);
       i = 0;

       i = ldns_bget_token(b, fkeyword, k_del, data_limit);

       /* case??? */
       if (strncmp(fkeyword, keyword, strlen(keyword)) == 0) {
               /* whee, the match! */
               /* retrieve it's data */
               i = ldns_bget_token(b, data, d_del, 0);
               return i;
       } else {
               return -1;
       }
}

