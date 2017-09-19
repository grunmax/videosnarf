/*
 *	VideoSnarf: A tool to read offline pcap file and dump containing video streams
 *	in H.264 format.
 *	This tool is a part of UCSniff: Next Generation VoIP Sniffer.
 *
 */
#include <pcap.h>
#include "videosnarf.h"
#include "stream.h"
#include "vsh264.h"


static pcap_t *fp;
int create_wav_header(FILE *, unsigned short, unsigned short, unsigned int, short);
static int fileWrite(char *, int, int, FILE *);
void decode_dot1q(const u_char*, u_char *);
static int checkPreviousSequence(struct MediaStream *);
static int dot1qYes,ethsize;

char *inputPcapFile;
char *outputBaseFile;
char *filterExpression;
int userFilterExpressionSet;
int userH264PTSet;
int userH264PayloadType;
int checkParameterSets;
int g726SampleSize;

extern struct MediaStream *Head;
extern struct MediaStream *Tail;
extern int streamCount;

/*
#define phtonl(p, v) \
        {                               \
        (p)[0] = (u_int8_t)((v) >> 24);   \
        (p)[1] = (u_int8_t)((v) >> 16);   \
        (p)[2] = (u_int8_t)((v) >> 8);    \
        (p)[3] = (u_int8_t)((v) >> 0);    \
        }

#define phtons(p, v) \
        {                               \
        ((u_int8_t*)(p))[0] = (u_int8_t)((v) >> 8); \
        ((u_int8_t*)(p))[1] = (u_int8_t)((v) >> 0); \
        }
*/

void mediasnarfStart()
{
    char errbuf[PCAP_ERRBUF_SIZE];
	char iface[] = "eth0";
	struct bpf_program bp;

	Head = NULL;
	Tail = NULL;
	streamCount = 0;

	if(userFilterExpressionSet == 0 && filterExpression == NULL){

		/* If there are 802.1Q headers in the packet pacture the libpcap filter expression does not work. The below code is commented until the libpcap
		   filter issues are fixed */
		/*
		char filter[] = "udp";
		filterExpression = (char *) calloc(strlen(filter) + 1, sizeof(char));
		if(filterExpression == NULL){
			printf("Not enough memory for allocation:%s\n",strerror(errno));
			exit(1);
		}
		strncpy(filterExpression,filter,strlen(filter));
		*/
	}

        if (inputPcapFile != NULL) {

			fp = pcap_open_offline(inputPcapFile, errbuf);
           	printf("[+] Please wait while decoding pcap file...\n");
        }
        else {
                printf("[+] Starting Sniffing on %s\n",iface);
                fp = pcap_open_live(iface, SNAPLEN, PROMISC, TIMEOUT, errbuf);
        }
        if ( fp == NULL ){
               fprintf(stderr, "[-] Unable to open pcap device:%s\n",errbuf);

        }

        /* make sure we're capturing on an Ethernet device [2] */
		/*
        if (pcap_datalink(fp) != DLT_EN10MB) {
                fprintf(stderr, "[-] %s is not an Ethernet\n", iface);
                exit(EXIT_FAILURE);
        }
		*/

	/*
	if(filterExpression == NULL){
		printf("Filter Expression cannot be null\n");
		exit(1);
	}
	*/
	if(filterExpression != NULL){

		if (pcap_compile(fp, &bp,filterExpression, 0,-1) < 0) {
            fprintf(stderr, "[-] Failed to compile filter expression.: %s\n",pcap_geterr(fp));
			exit(1);
      	}
		if (pcap_setfilter(fp, &bp)< 0) {
        	fprintf(stderr, "[-] Failed to set the compiled filter expression.:%s\n",pcap_geterr(fp));
            exit(1);
        }
	}

	if(pcap_datalink(fp) == DLT_RAW)
	{
		pcap_loop(fp, 0, packet_handler_rawip, NULL);
	}
	else if(pcap_datalink(fp) == DLT_LINUX_SLL)
	{
		pcap_loop(fp, 0, packet_handler_linuxcooked, NULL);
	}
	else
	{
    	pcap_loop(fp, 0, packet_handler, NULL);
	}
}

void packet_handler_rawip(u_char *dummy, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	dot1qYes = 0;
	ethsize = 0;

	decode_ip(pkt_data, (u_char *)dummy);
}

void packet_handler_linuxcooked(u_char *dummy, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	dot1qYes = 0;
	ethsize = LINUX_COOKED;

	decode_ip(pkt_data, (u_char *)dummy);
}

void packet_handler(u_char *dummy,const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	dot1qYes = 0;
	ethsize = ETHSIZE;
    const struct sniff_ethernet *ethernet;
    ethernet = (struct sniff_ethernet*)(pkt_data);
    switch(ntohs(ethernet->ether_type))
	{
		case ETHERTYPE_1Q:
			decode_dot1q(pkt_data,dummy);
			break;
		case ETHERTYPE_IP:
    		decode_ip(pkt_data,(u_char *)dummy);
        	break;
		default:
			ethsize = LINUX_COOKED;
			decode_ip(pkt_data,(u_char *)dummy);
    		break;
	}
}

void decode_dot1q(const u_char *pkt_data, u_char *dummy){

	const struct sniff_ethernet *ethernet;
	ethernet = (struct sniff_ethernet*)(pkt_data);
	const struct vlan_header *dot1q;
	dot1q = (struct vlan_header*)(pkt_data + ETHSIZE);
	dot1qYes = 1;
	switch(ntohs(dot1q->length)){

		case ETHERTYPE_IP:
			decode_ip(pkt_data,dummy);
			break;

		default:
			break;
	}
}

void decode_ip(const u_char *pkt_data, u_char *arg)
{
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;		/* The UDP Header */
	const struct sniff_rtp *rtp;		/* The RTP Header */
	unsigned char *payload;                    /* Packet payload */
	unsigned char *rBuffer = NULL;
	int len = 0, ret = 0;
	int size_ip = 0;
    int size_tcp = 0;
    int size_payload = 0;
	int csrcOffset = 0;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(pkt_data);

    /* define/compute ip header offset */
	if(dot1qYes)
	{
		ip = (struct sniff_ip*)(pkt_data + ethsize + sizeof(struct vlan_header));
	}
	else
	{
    	ip = (struct sniff_ip*)(pkt_data + ethsize);
	}
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20)
	{
    	printf("[-] Invalid IP header length: %u bytes\n", size_ip);
        return;
	}

    /* determine protocol */

	switch(ip->ip_p)
	{
		case IPPROTO_TCP:

			/* In the future we might add RTSP (TCP/UDP) support */
			break;

		case IPPROTO_UDP:

			if(dot1qYes)
			{
				udp = (struct sniff_udp *)(pkt_data + ethsize + sizeof(struct vlan_header) + size_ip);
				rtp = (struct sniff_rtp *)(pkt_data + ethsize + sizeof(struct vlan_header) + size_ip + UDPSIZE );
				u_char csrcCount = rtp->version & 0x0F;
				csrcOffset = (int) csrcCount * 4;
				payload = (u_char *)(pkt_data + ethsize + sizeof(struct vlan_header) + size_ip + UDPSIZE + RTPSIZE + csrcOffset);
			}
			else
			{
				udp = (struct sniff_udp *)(pkt_data + ethsize + size_ip);
                rtp = (struct sniff_rtp *)(pkt_data + ethsize + size_ip + UDPSIZE );
                u_char csrcCount = rtp->version & 0x0F;
                csrcOffset = (int) csrcCount * 4;
                payload = (u_char *)(pkt_data + ethsize + size_ip + UDPSIZE + RTPSIZE);
			}

			size_payload = htons(udp->len) - ( UDPSIZE +  RTPSIZE + csrcOffset);
			u_char ptype = rtp->payloadType & 0x7F;
			char srcIP[16], dstIP[16], pd[4];
			strncpy(srcIP,inet_ntoa(ip->ip_src),sizeof(srcIP));
			strncpy(dstIP,inet_ntoa(ip->ip_dst),sizeof(dstIP));

			int srcPort = 0;
			srcPort = (int)ntohs(udp->source);
			int dstPort = 0;
			dstPort = (int)ntohs(udp->dest);

			if ( ptype >= 0x60 && ptype <= 0x7F)
			{
				struct MediaStream *currentMS = streamHandler(srcIP,dstIP,srcPort,dstPort,(struct sniff_rtp *)rtp,h264,ptype);
				if(currentMS == NULL)
					return;
				if(currentMS->fp == NULL){
					printf("Error: Fwd fp is null\n");
					return;
				}

				currentMS->rtpPTR->sequence_no = ntohs(rtp->sequence_no);
				int dumpYes = checkPreviousSequence(currentMS);
                                if(!dumpYes)
                                        return;

				struct naluHeader naluHeaderValue;
      		    int writeNALPrefixCode = 1;
            	int writePacket = 1;
               	int offset = 0;
                u_char *value = payload;

                naluHeaderValue.forbidden = (*value & 0x80) >> 7;
                naluHeaderValue.nri = (*value & 0x60) >> 5;
                naluHeaderValue.type = *value & 0x1F;

				currentMS->count += 1;

				if(checkParameterSets == 1 && currentMS->receivedParameterSets == 0)
				{
					if(naluHeaderValue.type == 8 || naluHeaderValue.type == 7)
					{
						/* Received Picture paramter set or Sequence parameter set */
						currentMS->receivedParameterSets = 1;
					}
					else
					{
						return;
					}
				}

				if(naluHeaderValue.type == 28)
				{
                	parseH264FUANAL(&naluHeaderValue, &value, &offset, &writeNALPrefixCode, &writePacket, &currentMS->fuaStart);
              	}
				else if(naluHeaderValue.type == 24)
				{
                	/* STAP-A NAL aggregate packets */
                    parseH264STAPANAL(&value, size_payload, currentMS->mediaFileName, currentMS->fp, &writeNALPrefixCode, &writePacket);
                }
                else if(naluHeaderValue.type == 25)
				{
                	/* STAP-B NAL aggregate packets */
                    parseH264STAPBNAL(&value, size_payload, currentMS->mediaFileName, currentMS->fp, &writeNALPrefixCode, &writePacket);
                }
                else if(naluHeaderValue.type == 26)
				{
                	/* MTAP-16 Aggregate NAL Units */
                    parseH264MTAPNAL(&value, size_payload, currentMS->mediaFileName, currentMS->fp, &writeNALPrefixCode, &writePacket, 16);
                }
                else if(naluHeaderValue.type == 27)
				{
                	/* MTAP-32 NAL Aggregate Unit */
                    parseH264MTAPNAL(&value, size_payload, currentMS->mediaFileName, currentMS->fp, &writeNALPrefixCode, &writePacket, 24);
                }

				if(writeNALPrefixCode)
				{
   	            	phtonl(pd,0x00000001);
                   	fwrite(pd,1,4,currentMS->fp);
               	}

				if(writePacket)
				{
					size_t ret = fwrite(value, sizeof(u_char), (size_payload - offset), currentMS->fp);
                   	if(ret < (size_payload -  offset))
					{
                    	printf("Error: Writing data to file %s:%s \n",currentMS->mediaFileName,strerror(errno));
                    }
				}
			}
			else if ((ptype == 0x08) || (ptype == 0x00))
			{
				struct MediaStream *currentMS = NULL;
				short audio_format = 0;


				if(currentMS == NULL)
					return;

				if(currentMS->fp == NULL)
				{
					printf("error file pointer is null\n");
					return;
				}

				currentMS->rtpPTR->sequence_no = ntohs(rtp->sequence_no);
				int dumpYes = checkPreviousSequence(currentMS);
                if(!dumpYes)
                	return;

				currentMS->count += 1;

				if(currentMS->count == 1)
				{
					int return_wav = create_wav_header(currentMS->fp, 1, 8, 8000, audio_format);
					if(return_wav < 0)
					{
						printf("[-]Cannot write wav header file, wav file %s will be not be playable\n",currentMS->mediaFileName);
						return;
					}
				}

				dump_payload(payload,size_payload,currentMS->fp);
			}
			else if((ptype == COG722))
			{
				return;
			}
			else if(ptype == COG729)
			{
#ifndef ARCH_X64
					return;
#endif
			}
			else if(ptype == COG723)
			{
#ifndef ARCH_X64
					return;
#endif
			}
			else if(ptype == COG726)
			{
#ifndef ARCH_X64
                    return;
#endif
			}
			else
			{
				return;
			}
			break;
	default:
    	printf("Protocol: Unsupported\n");
		break;
	}
}

static int checkPreviousSequence(struct MediaStream *currentMS){


	if(currentMS->count == 0){

		currentMS->previousSequenceNo = currentMS->rtpPTR->sequence_no;
		return 1;
	}
	//else if(currentMS->previousSequenceNo == (currentMS->rtpPTR->sequence_no - 1)){
	else if(currentMS->rtpPTR->sequence_no > currentMS->previousSequenceNo){

		currentMS->previousSequenceNo = currentMS->rtpPTR->sequence_no;
		return 1;
	}
	else if((currentMS->previousSequenceNo == 65535) && (currentMS->rtpPTR->sequence_no == 0)){

		currentMS->previousSequenceNo = currentMS->rtpPTR->sequence_no;
                return 1;
	}
	return 0;
}

int dump_payload(unsigned char *payload,int plen, FILE *fp)
{
        int ret = fwrite(payload,sizeof(unsigned char),plen,fp);
        if ( ret < 0){
                fprintf(stderr,"[-] Failed to dump the payload.\n");
                return(1);
        }
        return(0);
}

int create_wav_header(FILE *fp, unsigned short NumChannels, unsigned short bitsPerSample, unsigned int sampleRate, short audio_format){

        if(fp == NULL){
                printf("Error: Null file pointer at create_wav_header\n");
                return -1;
        }

        unsigned short blockAlign = bitsPerSample / 8 * NumChannels;
        unsigned int avgBytesPerSecond = sampleRate * blockAlign;
        char pd[4];
        int ret = 0;

        phtonl(pd,0x52494646);                           /*RIFF header value */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        phtonl(pd,2048);                                 /*Length of the WAV file, right now it is just a sample value not the exact value */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        phtonl(pd,0x57415645);                          /*WAVE header value */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        phtonl(pd,0x666d7420);                          /*fmt header value */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        int val = 0x00000010;                           /*Length of the subchunk */
        memcpy(pd,&val,sizeof(int));
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        val = audio_format;                                     /*Audio Format, Using Linear PCM */
        memcpy(pd,&val,sizeof(short));
	if((ret = fileWrite(pd,1,2,fp)) < 0){
                return ret;
        }
        val = 0x0001;                                   /*Number of channels, 1 = Mono and 2 = Stereo */
        memcpy(pd,&val,sizeof(short));
        if((ret = fileWrite(pd,1,2,fp)) < 0){
                return ret;
        }
        memcpy(pd,&sampleRate,sizeof(unsigned int));                    /* Sampling Rate */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        memcpy(pd,&avgBytesPerSecond,sizeof(unsigned int));             /*Average Bytes per Second,calculated above */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        memcpy(pd,&blockAlign,sizeof(unsigned int));                    /*Block Align*/
        if((ret = fileWrite(pd,1,2,fp)) < 0){
                return ret;
        }
        memcpy(pd,&bitsPerSample,sizeof(unsigned int));                 /*Bits per sample */
        if((ret = fileWrite(pd,1,2,fp)) < 0){
                return ret;
        }
        phtonl(pd,0x64617461);                                          /*Data, indicates the following are Data chunks */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        return 0;
}

int create_wav_header_cpp(FILE *fp, unsigned short NumChannels, unsigned short bitsPerSample, unsigned int sampleRate, short audio_format){

        if(fp == NULL){
                printf("Error: Null file pointer at create_wav_header\n");
                return -1;
        }

        unsigned short blockAlign = bitsPerSample / 8 * NumChannels;
        unsigned int avgBytesPerSecond = sampleRate * blockAlign;
        char pd[4];
        int ret = 0;

        phtonl(pd,0x52494646);                           /*RIFF header value */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        phtonl(pd,2048);                                 /*Length of the WAV file, right now it is just a sample value not the exact value */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        phtonl(pd,0x57415645);                          /*WAVE header value */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        phtonl(pd,0x666d7420);                          /*fmt header value */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        int val = 0x00000010;                           /*Length of the subchunk */
        memcpy(pd,&val,sizeof(int));
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        val = audio_format;                                     /*Audio Format, Using Linear PCM */
        memcpy(pd,&val,sizeof(short));
    if((ret = fileWrite(pd,1,2,fp)) < 0){
                return ret;
        }
        val = 0x0001;                                   /*Number of channels, 1 = Mono and 2 = Stereo */
        memcpy(pd,&val,sizeof(short));
		if((ret = fileWrite(pd,1,2,fp)) < 0){
                return ret;
        }
        memcpy(pd,&sampleRate,sizeof(unsigned int));                    /* Sampling Rate */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        memcpy(pd,&avgBytesPerSecond,sizeof(unsigned int));             /*Average Bytes per Second,calculated above */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        memcpy(pd,&blockAlign,sizeof(unsigned int));                    /*Block Align*/
        if((ret = fileWrite(pd,1,2,fp)) < 0){
                return ret;
        }
        memcpy(pd,&bitsPerSample,sizeof(unsigned int));                 /*Bits per sample */
        if((ret = fileWrite(pd,1,2,fp)) < 0){
                return ret;
        }
        phtonl(pd,0x64617461);                                          /*Data, indicates the following are Data chunks */
        if((ret = fileWrite(pd,1,4,fp)) < 0){
                return ret;
        }
        return 0;
}

int fileWrite(char *buffer, int size, int nitems, FILE *fp){

        size_t ret = fwrite(buffer, size, nitems, fp);
        if(ret < nitems){
                printf("Error writing data at filwWrite:%s \n",strerror(errno));
                return -1;
        }
        return 0;

}

void mediasnarfStop(){

	deleteAllStreams();

}
