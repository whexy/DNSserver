# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#  License: The MIT License (MIT)
#
#  Copyright (c) 2020 SHI Wenxuan. -> www.whexy.com
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#  THE SOFTWARE.
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


import json
import time
from socket import *
from typing import List

from dnslib import DNSRecord, DNSQuestion, RR, QTYPE, DNSError

# FLAG SETTING

'''
    FLAG_TS_ITER is used to set whether NS record should be parsed by our DNS server.
    For example, we got no A records but several NS records (e.g. ns1.dnspod.com) from somewhere,
    and we can choose to:
    
    1. send next query directly with target domain name (NS_address, 53).
        That's easy but *cheating* because we are going to implement a DNS server.
    2. parse NS_address into IP (a TYPE.A record) by parsing the NS_address first.
        That's good but it's much more complicated.
    
    Set this flag to ``False`` can disable NS_address parsing, to make system output nice and simple.
'''
FLAG_TS_ITER = True


class DNSCache(object):
    def __init__(self):
        self.cache = {}

    def write_cache(self, response: DNSRecord):
        """
        Use DNS Response to cache RRs.

        :param response: a DNSRecord with answers
        """
        qname = response.q.qname
        qtype = response.q.qtype
        self.cache[qname, qtype] = (response.rr, int(time.time()))

    def read_cache(self, query: DNSRecord):
        """
        Use DNS Query to find cache RRs. If RR in cache is out-of-date, they will update.

        :param query: a DNSRecord with questions
        :return: reply a DNSRecord with answers if cached; None if not cached; None if cache out-of-date.
        """
        qname = query.q.qname
        qtype = query.q.qtype
        if (qname, qtype) in self.cache:
            reply = query.reply()
            rrs, record_time = self.cache[qname, qtype]
            for rr in rrs:
                ttl = rr.ttl - int(time.time()) + record_time
                if ttl <= 0:
                    print("\tLocal cache out-of-date.")
                    return None  # Cache out-of-date!
                reply.add_answer(RR(rr.rname, rr.rtype, rr.rclass, ttl, rr.rdata))
            return reply
        else:
            return None


class TargetServer(object):
    def __init__(self, query: DNSRecord, au: List[RR], ar: List[RR]):
        """
        Used to fetch target upstream DNS server from authority records and addition records.

        :param au: authority records
        :param ar: addition records
        """
        self.query = query
        self.au = au
        self.ar = ar

    def __iter__(self):
        """
        Iterator to return a target server

        :return: target server iterator
        """

        # Filter records with A type and NS type
        target_pool_a = []
        target_pool_a.extend([rr for rr in self.au if rr.rtype == QTYPE.A])
        target_pool_a.extend([rr for rr in self.ar if rr.rtype == QTYPE.A])
        target_pool_ns = []

        if FLAG_TS_ITER:
            target_pool_ns.extend([rr for rr in self.au if rr.rtype == QTYPE.NS])
            target_pool_ns.extend([rr for rr in self.ar if rr.rtype == QTYPE.NS])
        else:
            target_pool_a.extend([rr for rr in self.au if rr.rtype == QTYPE.NS])
            target_pool_a.extend([rr for rr in self.ar if rr.rtype == QTYPE.NS])

        if target_pool_a:
            # If target pool for Record Type A is not null, return iterator of target_pool_a
            # Warning: Drop all remaining NS Record.
            target_pool = [rr.rdata.toZone() for rr in target_pool_a]
            return iter(target_pool)
        else:
            # If target pool only have records with type NS, return iterator of parsed IP.
            print("\t\tNo Type A in target pool, requesting for NS server.")
            return self.get_ip_from_ns_server(target_pool_ns)

    def get_ip_from_ns_server(self, ns_pool):
        for ns in ns_pool:
            qname = ns.rdata.toZone()
            new_query = DNSRecord(header=self.query.header)
            new_query.add_question(DNSQuestion(qname))
            result = iter_query(new_query).a
            try:
                if result.rtype == QTYPE.A:
                    yield result.rdata.toZone()
            except:
                continue


def get_root_server():
    """
    Get Root Server from config file "ROOTServer.json".
    If file not exists, call ``refresh_root_server()`` to fetch DNS root server information.

    :return: auth RR and ar RR.
    """
    try:
        with open("ROOTServer.json", "r") as f:
            record_zone = json.loads(f.read())
            auth_zone = record_zone["auth_zone"]
            ar_zone = record_zone["ar_zone"]
            auth = RR.fromZone(auth_zone)
            ar = RR.fromZone(ar_zone)
            return auth, ar
    except FileNotFoundError:
        refresh_root_server()
        get_root_server()


def refresh_root_server(server="172.18.1.92", site="cra.moe"):
    """
    Refresh Root Server and write to ROOTServer.json.

    Simply make up a DNS request to DNS server (SUSTech: 172.18.1.92, 172.18.1.93),
    and query for an uncommon domain name **with RD=0**.
    If the domain is common, campus DNS server will return final result,
    which not necessarily contains root server information.

    :param server: DNS server, use campus as default.
    :param site: An uncommon domain name.
    """
    q = DNSRecord()
    q.header.set_rd(0)
    q.add_question(DNSQuestion(site))

    server_socket.sendto(q.pack(), (server, 53))
    msg_rev, _ = server_socket.recvfrom(2048)

    a = DNSRecord.parse(msg_rev)
    auth_zone = "\n".join([rr.toZone() for rr in a.auth])
    ar_zone = "\n".join([rr.toZone() for rr in a.ar])
    with open("ROOTServer.json", "w") as f:
        f.write(json.dumps(dict(auth_zone=auth_zone, ar_zone=ar_zone)))


server_socket = socket(AF_INET, SOCK_DGRAM)
server_socket.bind(('', 53))  # Set up UDP server at port 53
cache = DNSCache()
root_auth, root_ar = get_root_server()


def main():
    while True:
        message, client_address = server_socket.recvfrom(2048)
        query = DNSRecord.parse(message)  # parsed DNS Record
        print("Get DNS request from {0}".format(client_address[0]))

        rd = query.header.get_rd()
        print("\tRequesting for {0}, Type {1}, RD={2}".format(query.q.qname, query.q.qtype, rd))

        reply = cache.read_cache(query)
        if reply is not None:
            print("\tResponse with cached reply package")
            server_socket.sendto(reply.pack(), client_address)
        else:
            if rd == 0:
                # RD = 0, send root servers (auth, ar) back.
                print("\tResponse with root server information")
                reply = query.reply()
                [reply.add_auth(rr) for rr in root_auth]
                [reply.add_ar(rr) for rr in root_ar]
            else:
                # RD = 1, perform iterative query at server.
                upstream_resp = iter_query(query)
                reply = query.reply()
                [reply.add_answer(rr) for rr in upstream_resp.rr]
                [reply.add_auth(rr) for rr in upstream_resp.auth]
                [reply.add_ar(rr) for rr in upstream_resp.ar]
                cache.write_cache(reply)
            server_socket.sendto(reply.pack(), client_address)


def iter_query(query):
    """
    Query domain name iteratively.

    :param query: domain name
    :return: a ``DNSRecord`` with answer
    """
    print("\tTask: {}".format(query.q.qname.idna()))
    domain_iter = iter(query.q.qname.idna().split(".")[-2::-1])
    qname = ''
    ts = TargetServer(query, root_auth, root_ar)
    cur_resp = None
    for par in domain_iter:

        qname = par + '.' + qname  # qname {com. ->  baidu.com  -> www.baidu.com}
        cur_query = DNSRecord(header=query.header)
        cur_query.set_header_qa()
        cur_query.add_question(DNSQuestion(qname))

        for target in ts:
            print("\tQuery {} from {}".format(qname, target))
            cur_resp = dns_send(cur_query, target)
            if cur_resp:
                # If not timeout, set new target server and move to next domain part.
                ts = TargetServer(query, cur_resp.auth, cur_resp.ar)
                break
            else:
                print("\t\tTime out, reset target upper stream.")

    # CDN cases: No A records but CNAME/NS records. One more step to get IP Address.
    if cur_resp.a.rdata is None:
        cur_query = DNSRecord(header=query.header)
        cur_query.set_header_qa()
        cur_query.add_question(query.q)
        for target in ts:
            print("\tQuery {} from {}".format(qname, target))
            cur_resp = dns_send(cur_query, target)
            if cur_resp.a.rdata:
                break
            else:
                print("\t\tTime out, reset target upper stream.")
    print("\tTask {} end.".format(query.q.qname.idna()))
    return cur_resp


def dns_send(cur_query, target, timeout=3):
    """
    Send DNS query to target. Query time out will return None.

    :param cur_query: DNSRecord with question
    :param target: target server IP address
    :param timeout: timeout, default 1 second.
    :return: DNSRecord with answer. None if time out.
    """
    query_socket = socket(AF_INET, SOCK_DGRAM)
    query_socket.sendto(cur_query.pack(), (target, 53))
    query_socket.settimeout(timeout)
    try:
        cur_resp_msg, _ = query_socket.recvfrom(2048)
    except:
        return None
    try:
        reply = DNSRecord().parse(cur_resp_msg)
        return reply
    except DNSError:
        return None


if __name__ == '__main__':
    main()
