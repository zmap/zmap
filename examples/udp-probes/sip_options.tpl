OPTIONS sip:${RAND_ALPHA=8}@${DADDR} SIP/2.0
Via: SIP/2.0/UDP ${SADDR}:${SPORT};branch=${RAND_ALPHA=6}.${RAND_DIGIT=10};rport;alias
From: sip:${RAND_ALPHA=8}@${SADDR}:${SPORT};tag=${RAND_DIGIT=8}
To: sip:${RAND_ALPHA=8}@${DADDR}
Call-ID: ${RAND_DIGIT=10}@${SADDR}
CSeq: 1 OPTIONS
Contact: sip:${RAND_ALPHA=8}@${SADDR}:${SPORT}
Content-Length: 0
Max-Forwards: 20
User-Agent: ${RAND_ALPHA=8}
Accept: text/plain

