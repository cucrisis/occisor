import os
import re
import time
import random
import socket
import logging
import ipwhois
import xmlrpclib
import dns.rcode
import dns.flags
import dns.resolver
import dns.exception
import dns.rdatatype
import networkx as nx

# Global variables
OCCISOR_LOGGER_FILE_PATH = os.getenv('OCCISOR_LOGGER_FILE_PATH', 'occisor.log')
OCCISOR_GANDI_KEY = os.getenv('OCCISOR_GANDI_KEY', '')


# Setup logger
logger_format = "%(levelname)s | %(asctime)s | %(message)s"
logger = logging.getLogger('OCISSOR')

logger_file = logging.FileHandler(OCCISOR_LOGGER_FILE_PATH)
logger_console = logging.StreamHandler()
logger_console.setFormatter(logging.Formatter(logger_format))
logger_file.setFormatter(logging.Formatter(logger_format))

logger.addHandler(logger_console)
logger.addHandler(logger_file)
logger.setLevel(logging.INFO)


class NameServerInformation(object):
    def __init__(self, ns_hostname, ns_inet_list=[], ns_soa=False, ns_for_sell=False, ns_whois={}, errors=None):
        """
        Name Server Information.
        :param ns_hostname:
        :param ns_inet_list:
        :param ns_soa:
        :param ns_for_sell:
        :param ns_whois:
        """

        self.ns_for_sell = ns_for_sell
        self.ns_hostname = ns_hostname
        self.ns_whois = ns_whois
        self.ns_errors = errors
        self.ns_inet_list = ns_inet_list
        self.ns_soa = ns_soa

    def __str__(self):
        return str(self.ns_hostname)


class DomainNameScanner(object):
    def __init__(self, target, reporter=None, resolver='8.8.8.8', gandi_key=None, check_whois=False, inet6=False):
        """
        Domain Name Delegation Tree Scanner.
        :param target:
        :param reporter:
        :param resolver:
        :param gandi_key:
        :param check_whois:
        """
        self._gandi_api = xmlrpclib.ServerProxy("https://rpc.gandi.net/xmlrpc/")

        if not target:
            raise ValueError('target must be provided')

        # Set properties
        self._target = target if target.endswith('.') else '%s.' % target
        self._ns_root = self.get_root_server()
        self._gandi_key = gandi_key
        self._resolver = resolver
        self._reporter = reporter
        self._whois = check_whois
        self._inet6 = inet6

        # Target result Graph
        self._graph = nx.DiGraph(name='Delegation tree for %s' % self._target)
        self._thread_pool = list()

    @staticmethod
    def get_root_server_list():
        """
        return a list of root name servers
        :return:  list( {'INET': ,'HOSTNAME': },...)
        """
        return [
            {
                'INET': '198.41.0.4',
                'HOSTNAME': 'a.root-servers.net.'
            }, {
                'INET': '192.228.79.201',
                'HOSTNAME': 'b.root-servers.ne.'
            }, {
                'INET': '199.7.91.13',
                'HOSTNAME': 'c.root-servers.net.'
            }, {
                'INET': '192.203.230.10',
                'HOSTNAME': 'e.root-servers.net.'
            }, {
                'INET': '192.5.5.241',
                'HOSTNAME': 'f.root-servers.net.'
            }
        ]

    @staticmethod
    def get_root_server(inet=None, hostname=None):
        """
        if inet or hostname provided return a name server that match the property, otherwise return randomly one.
        :param inet:
        :param hostname:
        :return: {'INET': ,'HOSTNAME': }
        """

        if inet:
            target_ns = filter(lambda ns: ns['INET'] == inet, DomainNameScanner.get_root_server_list())
            if target_ns:
                return target_ns

        if hostname:
            target_ns = filter(lambda ns: ns['HOSTNAME'] == inet, DomainNameScanner.get_root_server_list())
            if target_ns:
                return target_ns

        return random.choice(DomainNameScanner.get_root_server_list())

    def get_resolver(self, resolver_inet=None):
        """
        create a DNS resolver with provided resolver_inet or self._resolver if resolver_inet is not provided.
        :param resolver_inet:
        :return:
        """
        resolver_client = dns.resolver.Resolver(configure=False)
        resolver_client.nameservers = [resolver_inet if resolver_inet else self._resolver]
        resolver_client.timeout = 1
        resolver_client.lifetime = 1
        return resolver_client

    def get_ns_inet_list(self, hostname):
        """
        return hostname ips by query self._resolver, for A & AAAA records. Empty list is returned if no result.
        :param hostname:
        :return:
        """
        results = list()
        try:
            for rtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                result = self.get_resolver().query(qname=str(hostname), rdtype=rtype, raise_on_no_answer=False)
                for r in result:
                    if r.rdtype == 28 and self._inet6:
                        results.append(str(r))
                    if r.rdtype == 1:
                        results.append(str(r))

            return results
        except dns.exception.DNSException:
            return results

    def is_hostname_for_sell(self, hostname):
        """
        Check if hostname is for sell.
        :param hostname:
        :return:
        """
        if hostname.endswith("."):
            hostname = hostname[:-1]

        result = self._gandi_api.domain.available(self._gandi_key, [hostname])
        counter = 0
        while result[hostname] == "pending" and counter < 10:
            counter += 1
            time.sleep(1)
            result = self._gandi_api.domain.available(self._gandi_key, [hostname])

        return result[hostname] == "available"

    def get_ns_whois(self, ns_hostname):
        """
        Return whois information
        :param ns_hostname:
        :return:
        """
        try:
            whois_result = ipwhois.IPWhois(
                socket.gethostbyname(str(ns_hostname))
            ).lookup_rdap(nir_field_list=['contacts'])['objects']

            whois_email_ns = set()
            for email in re.findall(r'[\w\.-]+@[\w\.-]+', str(whois_result)):
                ns = re.search("@[\w.]+", str(email))
                email_ns = ns.group().replace('@', '')
                whois_email_ns.add(email_ns)

            return {'whois': whois_result, 'contact_ns_list': whois_email_ns}
        except Exception:
            return {'whois':None, 'contact_ns_list': None}

    def get_ns_info(self, ns_hostname):
        """
        Get Name Server Information
        :param target:
        :param ns_hostname:
        :param ns_inet:
        :return:
        """

        ns_info = NameServerInformation(ns_hostname)
        ns_info.ns_inet_list = self.get_ns_inet_list(ns_hostname)
        ns_info.ns_whois = self.get_ns_whois(ns_hostname) if self._whois else {}
        ns_info.ns_for_sell = self.is_hostname_for_sell(ns_hostname) if self._gandi_key else False

        return ns_info

    def get_ns_list(self, target, ns_inet):
        """
        Get name server list for target.
        :param target:
        :param ns_inet:
        :return:
        """
        ns_list = set()

        try:
            re = self.get_resolver(ns_inet).query(qname=target, rdtype=dns.rdatatype.NS, raise_on_no_answer=False)

            for rrset in re.response.answer:
                for r in rrset:
                    ns_list.add(r)
            for rrset in re.response.authority:
                for r in rrset:
                    if hasattr(r, 'mname'):
                        ns_list.add(r.mname)
                    if hasattr(r, 'target'):
                        ns_list.add(r.target)
                    if hasattr(r, 'rname'):
                        ns_list.add(r.rname)
            for rrset in re.response.additional:
                ns_list.add(rrset.name)
            return ns_list, None, re, True if "AA" in dns.flags.to_text(re.response.flags).split(" ") else False
        except dns.exception.DNSException as error:
            ns_error = error
            return ns_list, ns_error, None, False

    def scan(self, ns_info=None):
        """
        Scan target delegation tree starting from ns_info. if target is None bootstrap with random root server.

        :param ns_info:
        :return:
        """

        # Bootstrap with random root ns
        ns_info = ns_info if ns_info else self.get_ns_info(self._ns_root['HOSTNAME'])

        # For each ip Query
        logger.info('@ Query each inet of %s for %s ' % (ns_info.ns_hostname, self._target))

        for inet in ns_info.ns_inet_list:
            # Query & Report & hook errors to object if present
            result_ns_list, result_ns_errors, response, ns_info.ns_soa = self.get_ns_list(self._target, inet)

            logger.info('- Q %s/%s for %s' % (ns_info.ns_hostname, inet, self._target))
            logger.info('-- %s' % ('Analyze' if not result_ns_errors else '%s Error found' % result_ns_errors))

            if result_ns_errors:
                ns_info.ns_errors = (result_ns_errors, inet)

            if not ns_info.ns_errors:
                logger.info('--- Query each ns list result of %s | %s' % (ns_info.ns_hostname, result_ns_list))

                for result_ns_hostname in result_ns_list:
                    logger.info('---- Q %s' % result_ns_hostname)

                    next_ns_info = self.get_ns_info(result_ns_hostname)
                    logger.info('------ Inet List: %s' % next_ns_info.ns_inet_list)
                    logger.info('------ Domain For Sale: %s' % next_ns_info.ns_for_sell)

                    logger.info('--- Create Nodes & Build Links for %s -> %s' % (str(ns_info), str(next_ns_info)))
                    if not self._graph.has_node(str(ns_info)):
                        self._graph.add_node(str(ns_info), {'ns_info': ns_info, 'key': str(ns_info)})
                    if not self._graph.has_node(str(next_ns_info)):
                        self._graph.add_node(str(next_ns_info), {'ns_info': next_ns_info, 'key': str(next_ns_info)})

                    self._graph.add_edge(str(ns_info), str(next_ns_info))

                    # Process whois
                    if self._whois:
                        if next_ns_info.ns_whois['contact_ns_list']:
                            for ns in next_ns_info.ns_whois['contact_ns_list']:
                                if not self._graph.has_node(ns):
                                    self._graph.add_node(ns, {'key': str(ns)})
                                self._graph.add_edge(str(next_ns_info), str(ns),  {
                                    'label': 'whois contact @', 'style': 'dotted'
                                })

                    # Prevent loop
                    if not str(ns_info) in self._graph.neighbors(str(next_ns_info)):
                        logger.info('Query %s' % result_ns_hostname)
                        self.scan(next_ns_info)

    def report(self):
        if self._reporter:
            self._reporter.report(self._target[:-1], self._graph)


