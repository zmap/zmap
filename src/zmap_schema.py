from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

zmap_base = Record({
    "saddr":IPv4Address(),
    "saddr_raw":Long(),
    "daddr":IPv4Address(),
    "daddr_raw":Long(),
    "ipid":Integer(),
    "ttl":Integer(),
    "classification":String(),
    "success":Integer(),
    "app_success":Integer(),
    "repeat":Integer(),
    "cooldown":Integer(),
    "timestamp_str":String(),
    "timestamp_ts":Long(),
    "timestamp_us":Long(),
    "icmp_responder":String(),
    "icmp_type":Integer(),
    "icmp_code":Integer(),
    "icmp_unreach_str":String(),
    "sport":Integer(),
    "dport":Integer(),
    "data":String(),
    "length":Integer(),

})

zmap_upnp = Record({
    "type":String(),
    "server":AnalyzedString(),
    "location":AnalyzedString(),
    "usn":String(),
    "st":String(),
    "ext":String(),
    "cache_control":String(),
    "x_user_agent":String(),
    "agent":String(),
    "date":String(),
}, extends=zmap_base)

zschema.registry.register_schema("zmap-upnp", zmap_upnp)


dns_question = SubRecord({
    "name":String(),
    "qtype":Integer(),
    "qtype_str":String(),
    "qclass":Integer(),
})

dns_answer = SubRecord({
  "name":String(),
  "type":Integer(),
  "type_str":String(),
  "class":Integer(),
  "ttl":Integer(),
  "rdlength":Integer(),
  "rdata_is_parsed":Integer(),
  "rdata":String(), # hex
})

zmap_dns = Record({
    "qr":Short(),
    "rcode":Short(),
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
    "dns_unconsumed_bytes":Integer(),
    "dns_parse_err":Integer(),
    "raw_data":String(),
    "udp_len":Integer(),
}, extends=zmap_base)

zschema.registry.register_schema("zmap-dns", zmap_dns)
