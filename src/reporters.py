import os
import logging
import tempfile
import transformer
import networkx as nx

logger = logging.getLogger('Reporter')


class ImageGenerationReporter(object):
    def __init__(self, output):
        if not output:
            output = tempfile.gettempdir()
        if not os.path.exists(output):
            os.mkdir(output)
        self.output = output

    def report(self, target, graph):
        logger.info('@ Building visual report for %s' % target)

        for key, information in graph.nodes_iter(data=True):
            logger.info('Drawing %s' % key)

            if 'ns_info' in information.keys():
                # Drawing
                # Create cyan box for SOA
                if information['ns_info'].ns_soa:
                    information['style'] = 'filled'
                    information['fillcolor'] = 'cyan'

                # Process Errors (error, inet)
                # # Create new node that represents the error type if doesn't exist
                if information['ns_info'].ns_errors:
                    # Get Error Key (the class name of the error)
                    ns_error_key = type(information['ns_info'].ns_errors[0]).__name__

                    # Create Node If Doesn't Exist
                    if ns_error_key not in graph.nodes():
                        ns_error_information = {'style': 'filled', 'fillcolor': 'Yellow', 'shape': 'octagon'}
                        if ns_error_key == 'NYDOMAIN':
                            ns_error_information['fillcolor'] = 'Red'

                        graph.add_node(ns_error_key, ns_error_information)

                    # Link between affected node and error node
                    graph.add_edge(key, ns_error_key, {'label': information['ns_info'].ns_errors[1]})

                # Process as NYDOMAIN error if no ns_inet_list present
                if not information['ns_info'].ns_inet_list:
                    ns_error_key = 'NYDOMAIN'
                    if ns_error_key not in graph.nodes():
                        graph.add_node(ns_error_key, {'style': 'filled', 'fillcolor': 'Red', 'shape': 'octagon'})
                    # Link between affected node and error node
                    graph.add_edge(key, ns_error_key, {'shape': 'vee'})

                # Process for sale
                if information['ns_info'].ns_for_sell:
                    information['style'] = 'filled'
                    information['shape'] = 'polygon'
                    information['fillcolor'] = 'orange'

        # Generate Graph
        pg = nx.nx_agraph.to_agraph(graph)
        pg.layout(prog='dot')
        pg.draw(os.path.join(self.output, '%s.png' % target))


class MaltegoTransformerReporter(object):
    def __init__(self, argv):
        self.maltego = transformer.MaltegoTransform()
        self.maltego.parseArguments(argv)
        self.maltego.addUIMessage('Occisor Transformer Created')

    def report(self, target, graph):
        self.maltego.addUIMessage('@ Building visual report for %s' % target)

        for key, information in graph.nodes_iter(data=True):
            self.maltego.addUIMessage('Creating %s' % key)

            if 'ns_info' in information.keys():
                # Create Maltego Entity
                self.create_maltego_graph(information['ns_info'], graph)

        self.maltego.returnOutput()

    def create_maltego_graph(self, ns_info, graph):
        if ns_info.ns_hostname not in self.maltego.entities:
            self.maltego.addEntity('maltego.Domain', str(ns_info.ns_hostname))

            for o in graph.neighbors(str(ns_info.ns_hostname)):
                logging.info(o)
                if hasattr(o, 'ns_hostname'):
                    self.create_maltego_graph(o, graph)