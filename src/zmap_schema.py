from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

zmap_base = Record({
    "saddr":IPv4Address(),
    "saddr_raw":Unsigned32BitInteger(),
    "daddr":IPv4Address(),
    "daddr_raw":Unsigned32BitInteger(),
    "ipid":Unsigned32BitInteger(),
    "ttl":Unsigned32BitInteger(),
    "classification":String(),
    "success":Unsigned32BitInteger(),
    "app_success":Unsigned32BitInteger(),
    "repeat":Unsigned32BitInteger(),
    "cooldown":Unsigned32BitInteger(),
    "timestamp_str":String(),
    "timestamp_ts":Unsigned32BitInteger(),
    "timestamp_us":Unsigned32BitInteger(),
    "icmp_responder":String(),
    "icmp_type":Unsigned32BitInteger(),
    "icmp_code":Unsigned32BitInteger(),
    "icmp_unreach_str":String(),
    "sport":Unsigned32BitInteger(),
    "dport":Unsigned32BitInteger(),
    "data":String(),
    "length":Unsigned32BitInteger(),

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
    "qtype":Unsigned32BitInteger(),
    "qtype_str":String(),
    "qclass":Unsigned32BitInteger(),
})

dns_answer = SubRecord({
  "name":String(),
  "type":Unsigned32BitInteger(),
  "type_str":String(),
  "class":Unsigned32BitInteger(),
  "ttl":Unsigned32BitInteger(),
  "rdlength":Unsigned32BitInteger(),
  "rdata_is_parsed":Unsigned32BitInteger(),
  "rdata":String(), # hex
})

zmap_dns = Record({
    "qr":Unsigned16BitInteger(),
    "rcode":Unsigned16BitInteger(),
    "dns_id":Unsigned32BitInteger(),
    "dns_rd":Unsigned32BitInteger(),
    "dns_tc":Unsigned32BitInteger(),
    "dns_aa":Unsigned32BitInteger(),
    "dns_opcode":Unsigned32BitInteger(),
    "dns_qr":Unsigned32BitInteger(),
    "dns_rcode":Unsigned32BitInteger(),
    "dns_cd":Unsigned32BitInteger(),
    "dns_ad":Unsigned32BitInteger(),
    "dns_z":Unsigned32BitInteger(),
    "dns_ra":Unsigned32BitInteger(),
    "dns_qdcount":Unsigned32BitInteger(),
    "dns_ancount":Unsigned32BitInteger(),
    "dns_nscount":Unsigned32BitInteger(),
    "dns_arcount":Unsigned32BitInteger(),
    "dns_questions":ListOf(dns_question),
    "dns_answers":ListOf(dns_answer),
    "dns_authorities":ListOf(dns_answer),
    "dns_additionals":ListOf(dns_answer),
    "dns_unconsumed_bytes":Unsigned32BitInteger(),
    "dns_parse_err":Unsigned32BitInteger(),
    "raw_data":String(),
    "udp_len":Unsigned32BitInteger(),
}, extends=zmap_base)

zschema.registry.register_schema("zmap-dns", zmap_dns)
