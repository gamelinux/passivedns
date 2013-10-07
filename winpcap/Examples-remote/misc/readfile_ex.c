#include <stdio.h>
#include <pcap.h>

#define LINE_LEN 16

int main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
char source[PCAP_BUF_SIZE];
struct pcap_pkthdr *header;
const u_char *pkt_data;
u_int i=0;
int res;

	if(argc != 2)
	{
		printf("usage: %s filename", argv[0]);
		return -1;
	}
	
	/* Create the source string according to the new WinPcap syntax */
	if ( pcap_createsrcstr(	source,			// variable that will keep the source string
							PCAP_SRC_FILE,	// we want to open a file
							NULL,			// remote host
							NULL,			// port on the remote host
							argv[1],		// name of the file we want to open
							errbuf			// error buffer
							) != 0)
	{
		fprintf(stderr,"\nError creating a source string\n");
		return -1;
	}
	
	/* Open the capture file */
	if ( (fp= pcap_open(source,			// name of the device
						65536,			// portion of the packet to capture
										// 65536 guarantees that the whole packet will be captured on all the link layers
						 PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
						 1000,				// read timeout
						 NULL,				// authentication on the remote machine
						 errbuf			// error buffer
						 ) ) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", source);
		return -1;
	}
	
	/* Retrieve the packets from the file */
	while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
	{
		/* print pkt timestamp and pkt len */
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);			
		
		/* Print the packet */
		for (i=1; (i < header->caplen + 1 ) ; i++)
		{
			printf("%.2x ", pkt_data[i-1]);
			if ( (i % LINE_LEN) == 0) printf("\n");
		}
		
		printf("\n\n");		
	}
	
	
	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
	}
	
	return 0;
}

