# Occisor

Name server delegation path scanner. 

## Summary 

This project was inspired by @MandatoryProgrammer Trusttrees tool, if you haven't checked it out please do. As trusttree
this tool also recursively follow all the possible delegation paths for a target and creates a graph strucutre of its relationship along the way. 


## Features
- Creates a graph, which can be analyzed processed or transformed to other structures
- Tracks whois contact email domain as part of the overall flow
- Tracks domain availability
- [TODO] Automatic Detection of potential takeover
- [TODO] Maltego Integration

## Execution 
```
INFO | 2017-07-27 00:23:19,381 | @ Query each inet of a.root-servers.net. for google.com. 
INFO | 2017-07-27 00:23:19,404 | - Q a.root-servers.net./198.41.0.4 for google.com.
INFO | 2017-07-27 00:23:19,404 | -- Analyze
INFO | 2017-07-27 00:23:19,404 | --- Query each ns list result of a.root-servers.net. | set([<DNS name a.gtld-servers.net.>, <DNS name j.gtld-servers.net.>, <DNS name e.gtld-servers.net.>, <DNS name i.gtld-servers.net.>, <DNS name d.gtld-servers.net.>, <DNS name m.gtld-servers.net.>, <DNS name h.gtld-servers.net.>, <DNS name c.gtld-servers.net.>, <DNS name l.gtld-servers.net.>, <DNS name g.gtld-servers.net.>, <DNS name b.gtld-servers.net.>, <DNS name k.gtld-servers.net.>, <DNS name f.gtld-servers.net.>])
INFO | 2017-07-27 00:23:19,405 | ---- Q a.gtld-servers.net.
INFO | 2017-07-27 00:23:19,683 | ------ Inet List: ['192.5.6.30']
INFO | 2017-07-27 00:23:19,683 | ------ Domain For Sale: False
INFO | 2017-07-27 00:23:19,683 | ------ Domain Whois Information: set(['verisign.com'])
INFO | 2017-07-27 00:23:19,683 | --- Create Nodes & Build Links for a.root-servers.net. -> a.gtld-servers.net.
INFO | 2017-07-27 00:23:19,683 | Query a.gtld-servers.net.
INFO | 2017-07-27 00:23:19,683 | @ Query each inet of a.gtld-servers.net. for google.com. 
INFO | 2017-07-27 00:23:19,706 | - Q a.gtld-servers.net./192.5.6.30 for google.com.
INFO | 2017-07-27 00:23:19,706 | -- Analyze
INFO | 2017-07-27 00:23:19,707 | --- Query each ns list result of a.gtld-servers.net. | set([<DNS name ns3.google.com.>, <DNS name ns4.google.com.>, <DNS name ns1.google.com.>, <DNS name ns2.google.com.>])
INFO | 2017-07-27 00:23:19,707 | ---- Q ns3.google.com.
INFO | 2017-07-27 00:23:19,985 | ------ Inet List: ['216.239.36.10']
INFO | 2017-07-27 00:23:19,985 | ------ Domain For Sale: False
INFO | 2017-07-27 00:23:19,985 | ------ Domain Whois Information: set(['google.com'])
INFO | 2017-07-27 00:23:19,985 | --- Create Nodes & Build Links for a.gtld-servers.net. -> ns3.google.com.
INFO | 2017-07-27 00:23:19,986 | Query ns3.google.com.
INFO | 2017-07-27 00:23:19,986 | @ Query each inet of ns3.google.com. for google.com. 
INFO | 2017-07-27 00:23:20,026 | - Q ns3.google.com./216.239.36.10 for google.com.
INFO | 2017-07-27 00:23:20,027 | -- Analyze
INFO | 2017-07-27 00:23:20,027 | --- Query each ns list result of ns3.google.com. | set([<DNS name ns4.google.com.>, <DNS IN NS rdata: ns4.google.com.>, <DNS name ns1.google.com.>, <DNS name ns2.google.com.>, <DNS name ns3.google.com.>, <DNS IN NS rdata: ns3.google.com.>, <DNS IN NS rdata: ns1.google.com.>, <DNS IN NS rdata: ns2.google.com.>])
INFO | 2017-07-27 00:23:20,027 | ---- Q ns4.google.com.
INFO | 2017-07-27 00:23:20,322 | ------ Inet List: ['216.239.38.10']
INFO | 2017-07-27 00:23:20,322 | ------ Domain For Sale: False
INFO | 2017-07-27 00:23:20,323 | ------ Domain Whois Information: set(['google.com'])
INFO | 2017-07-27 00:23:20,323 | --- Create Nodes & Build Links for ns3.google.com. -> ns4.google.com.
INFO | 2017-07-27 00:23:20,323 | Query ns4.google.com.
INFO | 2017-07-27 00:23:20,323 | @ Query each inet of ns4.google.com. for google.com. 
INFO | 2017-07-27 00:23:20,361 | - Q ns4.google.com./216.239.38.10 for google.com.
INFO | 2017-07-27 00:23:20,361 | -- Analyze
INFO | 2017-07-27 00:23:20,361 | --- Query each ns list result of ns4.google.com. | set([<DNS name ns4.google.com.>, <DNS IN NS rdata: ns4.google.com.>, <DNS name ns1.google.com.>, <DNS name ns2.google.com.>, <DNS name ns3.google.com.>, <DNS IN NS rdata: ns3.google.com.>, <DNS IN NS rdata: ns1.google.com.>, <DNS IN NS rdata: ns2.google.com.>])
INFO | 2017-07-27 00:23:20,361 | ---- Q ns4.google.com.
INFO | 2017-07-27 00:23:20,653 | ------ Inet List: ['216.239.38.10']
INFO | 2017-07-27 00:23:20,654 | ------ Domain For Sale: False
INFO | 2017-07-27 00:23:20,654 | ------ Domain Whois Information: set(['google.com'])
INFO | 2017-07-27 00:23:20,654 | --- Create Nodes & Build Links for ns4.google.com. -> ns4.google.com.
INFO | 2017-07-27 00:23:20,654 | ---- Q ns4.google.com.

[...snip..]

INFO | 2017-07-27 00:30:01,269 | @ Building visual report for google.com
INFO | 2017-07-27 00:30:01,269 | Drawing ns1.google.com.
INFO | 2017-07-27 00:30:01,269 | Drawing ns2.google.com.
INFO | 2017-07-27 00:30:01,270 | Drawing b.gtld-servers.net.
INFO | 2017-07-27 00:30:01,270 | Drawing m.gtld-servers.net.
INFO | 2017-07-27 00:30:01,270 | Drawing d.gtld-servers.net.
INFO | 2017-07-27 00:30:01,270 | Drawing google.com
INFO | 2017-07-27 00:30:01,270 | Drawing h.gtld-servers.net.
INFO | 2017-07-27 00:30:01,270 | Drawing j.gtld-servers.net.


```
## Example ImageGenerationReporter Graph
[![g](https://github.com/cucrisis/occisor/blob/master/resources/ticonsultores.biz.ni.png?raw=true)](https://github.com/cucrisis/occisor/blob/master/resources/ticonsultores.biz.ni.png?raw=true)

## Development
*Creation of DomainNameScanner:*
```python
scaner = DomainNameScanner(target='google.com', reporter=Reporter('output_images'))
scaner.scan()
scaner.report()

```

*Create custom Reporter:*
```python
class CustomReporter(object):
	def __init__():
		...

	def reporter(self, target, graph):
		for key, information in graph.nodes_iter(data=True)
			...

scaner = DomainNameScanner(target='example.com', reporter=CustomReporter())
scaner.scan()
scaner.report()

```

