from zschema import *

zmap_upnp = Record({
    "type":String(),
    "saddr":IPv4Address(),
    "saddr-raw":Long(),
    "daddr":IPv4Address(),
    "daddr-raw":Long(),
    "ipid":Integer(),
    "ttl":Integer(),
    "classification":String(),
    "success":Integer(),
    "server":AnalyzedString(),
    "location":AnalyzedString(),
    "usn":String(),
    "st":String(),
    "ext":String(),
    "cache-control":String(),
    "x-user-agent":String(),
    "agent":String(),
    "date":String(),
    "sport":Integer(),
    "dport":Integer(),
    "data":String(),
    "length":Integer(),
    "repeat":Integer(),
    "cooldown":Integer(),
    "timestamp-str":DateTime(),
    "timestamp-ts":Long(),
    "timestamp-us":Long(),

    "icmp_responder":String(),
    "icmp_type":Integer(),
    "icmp_code":Integer(),
    "icmp_unreach_str":String()
})

register_schema("zmap-upnp", zmap_upnp)


dns_question = SubRecord({
    "name":String(),
    "qtype":Integer(),
    "qtype_str":String(),
    "qclass":Integer(),
})

dns_answer = SubRecord({
  "name":String(),
  "type":Integer(),
  "class":Integer(),
  "ttl":Integer(),
  "rdlength":Integer(),
  "rdata_is_parsed":Integer(),
  "rdata":String(), # hex  
})

zmap_dns = Record({
        "qr":Short(),
        "rcode":Short(),
        "classification":String(),
        "success":Short(),
        "app_success":Short(),
        "sport":Short(),
        "dport":Short(),
        "len":Integer(),
        "icmp_responder":String(),
        "icmp_type":String(),
        "icmp_code":Integer(),
        "icmp_unreach_str":String(),
        "dns_id":Integer(),
        "dns_rd":Integer(),
        "dns_tc":Integer(),
        "dns_aa":Integer(),
        "dns_opcode":Integer(),
        "dns_qr":Integer(),
        "dns_rcode":Integer(),
        "dns_cd":Integer(),
        "dns_ad":Integer(),
        "dns_z":Integer(),
        "dns_ra":Integer(),
        "dns_qdcount":Integer(),
        "dns_ancount":Integer(),
        "dns_nscount":Integer(),
        "dns_arcount":Integer(),
        "dns_questions":ListOf(dns_question),
        "dns_answers":ListOf(dns_answer),
        "dns_authorities":ListOf(dns_answer),
        "dns_additionals":ListOf(dns_answer),
        "dns_unconsumed_bytes":String(), 
        "dns_parse_err":Integer(),
        "raw_data":String(),
})

register_schema("zmap-dns", zmap_dns)
