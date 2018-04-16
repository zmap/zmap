/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#pragma once

static fielddef_t fields[] = {
		{.name = "sport",  .type = "int", .desc = "TCP source port"},
		{.name = "dport",  .type = "int", .desc = "TCP destination port"},
		{.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
		{.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
		{.name = "window", .type = "int", .desc = "TCP window"},
		{.name = "tcpmss", .type = "int", .desc = "TCP mss"},
		{.name = "tsval", .type = "int", .desc = "tsval"},
		{.name = "tsecr", .type = "int", .desc = "tsecr"},
		{.name = "tsdiff", .type = "int", .desc = "tsval"},
		{.name = "qsfunc", .type = "int", .desc = "qsfunc"},
		{.name = "qsttl", .type = "int", .desc = "qsttl"},
		{.name = "qsnonce", .type = "int", .desc = "qsnonce"},
		{.name = "echo", .type = "int", .desc = "echo"},
		{.name = "echoreply", .type = "int", .desc = "echoreply"},
		{.name = "wscale", .type = "int", .desc = "tsval"},
		{.name = "mptcpkey", .type = "string", .desc = "tsval"},
		{.name = "mptcpdiff", .type = "int", .desc = "tsval"},
		{.name = "tfocookie", .type = "int", .desc = "tsval"},
		{.name = "optionshex", .type = "string", .desc = "TCP options"},
		{.name = "optionstext", .type = "string", .desc = "TCP options"},
		{.name = "classification", .type="string", .desc = "packet classification"},
		{.name = "success", .type="int", .desc = "is response considered success"}
};

static inline void tcpsynopt_process_packet_parse(
	__attribute__((unused)) uint32_t len, fieldset_t *fs,
	struct tcphdr *tcp, __attribute__((unused)) unsigned int optionbytes2)
	{
	char* opts = (char*)&tcp[1];
	static char* buf;
	buf = xmalloc(200); // buf[200];
	static char* buft;
	buft = xmalloc(200); // buf[200];

	fs_add_uint64(fs, "sport", (uint64_t) ntohs(tcp->th_sport));
	fs_add_uint64(fs, "dport", (uint64_t) ntohs(tcp->th_dport));
	fs_add_uint64(fs, "seqnum", (uint64_t) ntohl(tcp->th_seq));
	fs_add_uint64(fs, "acknum", (uint64_t) ntohl(tcp->th_ack));
	fs_add_uint64(fs, "window", (uint64_t) ntohs(tcp->th_win));
	fs_add_uint64(fs, "tcpmss", (uint64_t) 0);
	fs_add_uint64(fs, "tsval", (uint64_t) 0);
	fs_add_uint64(fs, "tsecr", (uint64_t) 0);
	fs_add_uint64(fs, "tsdiff", (uint64_t) 1);
	fs_add_uint64(fs, "qsfunc", (uint64_t) 0);
	fs_add_uint64(fs, "qsttl", (uint64_t) 0);
	fs_add_uint64(fs, "qsnonce", (uint64_t) 0);
	fs_add_uint64(fs, "echo", (uint64_t) 0);
	fs_add_uint64(fs, "echoreply", (uint64_t) 0);
	fs_add_uint64(fs, "wscale", (uint64_t) 0);
	fs_add_string(fs, "mptcpkey", (char*) "--",0);
	fs_add_uint64(fs, "mptcpdiff", (uint64_t) 0);
	fs_add_uint64(fs, "tfocookie", (uint64_t) 0);

	ntohs(tcp->th_off);
	// tcp->th_off = # of 32-bit words in header, of which 5 are basic header
	unsigned int option_bytes = (4*((unsigned int) 0xf & tcp->th_off))- sizeof(struct tcphdr);
	//if(optionbytes2 != option_bytes){
	//	printf("optionbytes2 (%u) != ob1 (%u) ; len=%u\n",optionbytes2, option_bytes,len);
	//}
	if(option_bytes > 40){
		printf("TCP options > 40 bytes! (%u) bytes. \n",option_bytes);
	}
	unsigned int i=0;
	snprintf(buf,3,"0x");
	for (i=0;i<option_bytes && i<40;i++){
		snprintf(&buf[i*2+2],3,"%02x",0xff & opts[i]);
	}
	// safety stop
	buf[41*2+2] = '\0';
	unsigned int j=0;
	// inspired by https://nmap.org/book/osdetect-methods.html
	// ts rfc: https://www.ietf.org/rfc/rfc1323.txt
	// iana tcp options: http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
	unsigned char cur;
	
	for (i=0;i<option_bytes;){
		cur=0xff & opts[i];
		if(j>180){
			snprintf(&buft[j],10,"OVERFLOW!");
			i=option_bytes;
			break;
		}
		switch(cur) {
		case 0:
			if(	(0xff & opts[i+1]) == 0 &&
				(0xff & opts[i+2]) == 0 &&
				(0xff & opts[i+3]) == 0)
			{
				snprintf(&buft[j],3,"E-"); j=j+2; // End of Options
			} else {
				snprintf(&buft[j],2,"X"); j++;				
			}
			i=option_bytes;		
			break;
		case 1: // NOP
			snprintf(&buft[j],3,"N-"); j=j+2;
			i++;
			break;
		case 2: // MSS
			if( (0xff & opts[i+1]) == 4){
				snprintf(&buft[j],5,"MSS-"); j=j+4;
				fs_modify_uint64(fs, "tcpmss", (uint64_t)(ntohs(*(unsigned short*) &opts[i+2])));
				i=i+4;
			} else { // invalid case, exit parsing
				snprintf(&buft[j],5,"MXX-"); j=j+4;
				i=option_bytes;
			}
			break;
		case 3: // Window Scale
			snprintf(&buft[j],4,"WS-"); j=j+3;
			fs_modify_uint64(fs, "wscale", (uint64_t) (0xff &opts[i+2]));
			i=i+3;
			break;
		case 4: // SACK permitted
			snprintf(&buft[j],6,"SACK-"); j=j+5;
			i=i+2;
			break;
		case 6: // Echo Request
			snprintf(&buft[j],5,"ECHO-"); j=j+5;
			fs_modify_uint64(fs, "echo", (uint64_t)(ntohl(*(unsigned int*) &opts[i+2])));
			i=i+6;
		case 7: // Echo Reply
			snprintf(&buft[j],6,"ECHOR-"); j=j+6;
			fs_modify_uint64(fs, "echoreply", (uint64_t)(ntohl(*(unsigned int*) &opts[i+2])));
			i=i+6;
		case 8: // timestamps
			if( (0xff & opts[i+1]) == 0x0a){
				snprintf(&buft[j],4,"TS-"); j=j+3;
				fs_modify_uint64(fs, "tsval", (uint64_t)(ntohl(*(unsigned int*) &opts[i+2])));
				fs_modify_uint64(fs, "tsecr", (uint64_t)(ntohl(*(unsigned int*) &opts[i+6])));
				fs_modify_uint64(fs, "tsdiff", (uint64_t) 1^(*(unsigned int*) &opts[i+2]==*(unsigned int*) &opts[i+6]));
				i=i+10;
			} else {
				snprintf(&buft[j],5,"TXX-"); j=j+4;
				i=option_bytes;
			}
			break;
		case 27: // Quick Start/ Response
			snprintf(&buft[j],3,"QS-"); j=j+3;

			fs_modify_uint64(fs, "qsfunc", (uint64_t)((*(unsigned char*) &opts[i+2]) >> 4));
			fs_modify_uint64(fs, "qsttl", (uint64_t)(*(unsigned char*) &opts[i+3]));
			fs_modify_uint64(fs, "qsnonce", (uint64_t)(ntohl((*(unsigned int*) &opts[i+4])>> 2)));
			i=i+8;
			break;
		case 30: // MPTCP
			snprintf(&buft[j],7,"MPTCP-"); j=j+6;
			// check that key is different from sent key
			static char *mptcpbuf;
			mptcpbuf = xmalloc(19+19); // should be 19, but safety buffer it!
			//snprintf(mptcpbuf,19,"0x%016llx", (unsigned long long)*(uint64_t*) &opts[i+4]);
			snprintf(&mptcpbuf[0],3,"0x");
			snprintf(&mptcpbuf[2],3,"%02x",0xff & opts[i+4]);
			snprintf(&mptcpbuf[4],3,"%02x",0xff & opts[i+5]);
			snprintf(&mptcpbuf[6],3,"%02x",0xff & opts[i+6]);
			snprintf(&mptcpbuf[8],3,"%02x",0xff & opts[i+7]);
			snprintf(&mptcpbuf[10],3,"%02x",0xff & opts[i+8]);
			snprintf(&mptcpbuf[12],3,"%02x",0xff & opts[i+9]);
			snprintf(&mptcpbuf[14],3,"%02x",0xff & opts[i+10]);
			snprintf(&mptcpbuf[16],3,"%02x",0xff & opts[i+11]);
			fs_modify_string(fs, "mptcpkey", (char*) mptcpbuf,1);
			fs_modify_uint64(fs, "mptcpdiff", 1^(0x0c0c0c0c0c0c0c0c == *(uint64_t*)&opts[i+4]));

			i=i+(unsigned int)(0xff & opts[i+1]);
			break;
		case 34: // TFO
				if((unsigned int)(0xff & opts[i+1])>2){
					// response with cookie
					snprintf(&buft[j],6,"TFOC-"); j=j+5;
					fs_modify_uint64(fs, "mptcpdiff", (uint64_t) 0);
					static char *tfobuf;
					tfobuf = xmalloc(60); // 2(0x) + 16*2 (1byte=2hexzahlen) + delim
					snprintf(&tfobuf[0],3,"0x");
					for (unsigned int k=2;k<(unsigned int)(0xff & opts[i+1]) && ((2+(k-2)*2) < 40);k++){
						snprintf(&tfobuf[2+(k-2)*2],3,"%02x",0xff & opts[i+k]); 
					}
					fs_modify_string(fs, "tfocookie", (char*)tfobuf,1);

				} else {
					// tfo reply without cookie (stupid middlebox option echo)
					snprintf(&buft[j],6,"TFOE-"); j=j+5;
				}
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;	
		case 64: // unknown option sent by us								
				snprintf(&buft[j],3,"U-"); j=j+2;
				i=i+2;
				break;									
	// CASES THAT SHOULD NOT APPEAR
		case 5: // SACK, only permitted in SYN
				snprintf(&buft[j],2,"X"); j++;
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;
		case 9: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+2;
				break;
		case 10: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+3;
				break;
		case 14: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+3;
				break;
		case 15: // SACK, only permitted in SYN
				snprintf(&buft[j],2,"X"); j++;
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;
		case 18: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+3;
				break;
		case 19: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+18;
				break;
		case 28: // obsolete
				snprintf(&buft[j],2,"X"); j++;
				i=i+4;
				break;	
		case 253: // experimental
				snprintf(&buft[j],2,"X"); j++;
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;	
		case 254: // experimental
				snprintf(&buft[j],2,"X"); j++;
				i=i+ (unsigned int)(0xff & opts[i+1]);
				break;	
		default: // even crazier crazyness ...  
			// unrec. option
			snprintf(&buft[j],3,"X-"); j=j+2;
			i=option_bytes;
			break;
		}	
	}
	
	fs_add_string(fs, "optionshex", (char*) buf, 1); // set to 1 to avoid mem leak
	fs_add_string(fs, "optionstext", (char*) buft, 1); // set to 1 to avoid mem leak

	if (tcp->th_flags & TH_RST) { // RST packet
		fs_add_string(fs, "classification", (char*) "rst", 0);
		fs_add_uint64(fs, "success", 0);
	} else { // SYNACK packet
		fs_add_string(fs, "classification", (char*) "synack", 0);
		fs_add_uint64(fs, "success", 1);
	}

}

