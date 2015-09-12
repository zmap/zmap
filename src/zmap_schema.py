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
