__author__ = "Grant Curell"
__copyright__ = "Do what you want with it"
__license__ = "GPLv3"
__version__ = "1.0.0"
__maintainer__ = "Grant Curell"

"""
An OpenFlow 1.3 TrafficShaper implementation
"""

import json
import sys
import urllib3
from webob import Response
from ryu.ofproto.ofproto_v1_3_parser import OFPMatch, OFPActionOutput
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.app.wsgi import WSGIApplication, route
from ryu.app.ofctl_rest import StatsController, RestStatsApi
from ryu.cmd import manager
from collections import defaultdict
from typing import List

ryu_instance = 'ryu_app'

def remove_all_flows(datapath: Datapath):
    """
    Removes all the flows from a switch.

    :param datapath: A Datapath object which represents the switch from which we want to remove flows
    """

    match = datapath.ofproto_parser.OFPMatch()
    mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, datapath.ofproto.OFPTT_ALL,
                                             datapath.ofproto.OFPFC_DELETE,
                                             0, 0, 0, 0xffffffff,
                                             datapath.ofproto.OFPP_ANY,
                                             datapath.ofproto.OFPG_ANY,
                                             0, match, [])

    datapath.send_msg(mod)


def add_flow(datapath: Datapath, priority: int, match: OFPMatch, actions: [OFPActionOutput], idle_timeout: int = 300,
             hard_timeout: int = 300):
    """
    Send a flow to the switch to be added to the flow table

    :param datapath: A Datapath object which represents the switch to which we want to add the flow
    :param priority: The priority of the flow. Should be higher than zero. Zero is the default flow used when traffic
                     does not match and should be sent to the controller.
    :param match: An OFPMatch object containing the match criteria for this flow
    :param actions: The actions you want applied if there is a flow match.
    :param idle_timeout: The timeout for the flow if the switch receives no matching packets. 0 is no timeout.
    :param hard_timeout: The timeout for the flow regardless if the switch does or doesn't receive packets.
                         0 is no timeout.
    """

    ofproto = datapath.ofproto

    # Same as ofproto, indicates the ofproto_parser module. In the case of OpenFlow 1.3 format will be following
    # module. ryu.ofproto.ofproto_v1_3_parser
    parser = datapath.ofproto_parser

    # construct flow_mod message and send it.
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                         actions)]

    # The class corresponding to the Flow Mod message is the OFPFlowMod class. The instance of the OFPFlowMod
    # class is generated and the message is sent to the OpenFlow switch using the Datapath.send_msg() method.
    mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                            idle_timeout=idle_timeout, hard_timeout=hard_timeout)
    datapath.send_msg(mod)


class RyuController:
    """
    This is the main Ryu app that is the Ryu controller

    In order to implement as a Ryu application, ryu.base.app_manager.RyuApp is inherited. Also, to use OpenFlow 1.3, the
    OpenFlow 1.3 version is specified for OFP_VERSIONS.

    Attributes:
        mac_to_port (dict): Used to store information mapping MAC addresses to a specific port
        flow_table (dict): Used to store flow information mapped to a specific port. If the controller receives a packet
                           not already associated with a flow, it creates a flow entry and then maps it to an outbound
                           port
        round_robin (int): Used to keep track of the next port a flow should be assigned to. We use this to load balance
                           flows across multiple ports.
        switches (dict): A dictionary of form {dpid: Datapath} with all of the devices being managed by this controller
        in_ports (defaultdict): Used to keep track of all ports expected to be used for inbound traffic.
        out_ports (defaultdict): Used to keep track of all the ports used for outbound traffic

    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RyuController, self).__init__(*args, **kwargs)
        # mac_to_port is the MAC address table for the switch
        self.mac_to_port = {}
        self.flow_table = {}
        self.round_robin = 0
        self.switches = {}
        self.in_ports = defaultdict(list)
        self.out_ports = defaultdict(list)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        See https://osrg.github.io/ryu-book/en/html/switching_hub.html#event-handler for description.
        See https://osrg.github.io/ryu-book/en/html/switching_hub.html#adding-table-miss-flow-entry for the rest of the
        function details.

        This function handles the ryu.controller.handler.CONFIG_DISPATCHER state. This state is used to handle waiting
        to receive SwitchFeatures message.

        :param ev: The switch event object containing the message data For this function we expect an instance of
                   ryu.ofproto.ofproto_v1_3_parser.OFPSwitchFeatures
        :return:
        """

        # In datapath we expect the instance of the ryu.controller.controller.Datapath class corresponding to the
        # OpenFlow switch that issued this message is stored. The Datapath class performs important processing such as
        # actual communication with the OpenFlow switch and issuance of the event corresponding to the received message.
        datapath = ev.msg.datapath

        # Indicates the ofproto module that supports the OpenFlow version in use. In the case of OpenFlow 1.3 format
        # will be following module. ryu.ofproto.ofproto_v1_3
        ofproto = datapath.ofproto

        # Same as ofproto, indicates the ofproto_parser module. In the case of OpenFlow 1.3 format will be following
        # module. ryu.ofproto.ofproto_v1_3_parser
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        # The Table-miss flow entry has the lowest (0) priority and this entry matches all packets. In the instruction
        # of this entry, by specifying the output action to output to the controller port, in case the received packet
        # does not match any of the normal flow entries, Packet-In is issued.
        #
        # An empty match is generated to match all packets. Match is expressed in the OFPMatch class.
        #
        # Next, an instance of the OUTPUT action class (OFPActionOutput) is generated to transfer to the controller
        # port. The controller is specified as the output destination and OFPCML_NO_BUFFER is specified to max_len in
        # order to send all packets to the controller.
        match = parser.OFPMatch()

        actions: List[OFPActionOutput] = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        # Clear out all existing flows on the switch before continuing
        remove_all_flows(datapath)

        match_in = parser.OFPMatch(
            in_port=5,
            eth_type=int("800", 16),  # This is a prerequisite for matching against IPv4 packets
            ip_proto=6,  # This is a prerequisite for matching against TCP segments
            ipv4_src="192.168.1.8",
            ipv4_dst="192.168.1.7",
            tcp_src=80,
            tcp_dst=8888)
        match_out = parser.OFPMatch(
            in_port=9,
            eth_type=int("800", 16),
            ip_proto=6,  # This is TCP
            ipv4_dst="192.168.1.8",
            ipv4_src="192.168.1.7",
            tcp_dst=80,
            tcp_src=8888)

        # Finally, 0 (lowest) is specified for priority and the add_flow() method is executed to send the Flow Mod
        # message. The content of the add_flow() method is explained in a later section.
        add_flow(datapath, 0, match, actions, 0, 0)

        # Add two flows with very low timeouts to illustrate the problem.
        add_flow(datapath, 2, match_in, actions, 5, 5)
        add_flow(datapath, 2, match_out, actions, 5, 5)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """
        Handle EventOFPFlowRemoved messages

        :param ev: The switch event object containing the message data For this function we expect an instance of
           ryu.ofproto.ofproto_v1_3_parser.OFPSwitchFeatures
        """
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'

        self.logger.debug('OFPFlowRemoved received: '
                          'cookie=%d priority=%d reason=%s table_id=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'idle_timeout=%d hard_timeout=%d '
                          'packet_count=%d byte_count=%d match.fields=%s',
                          msg.cookie, msg.priority, reason, msg.table_id,
                          msg.duration_sec, msg.duration_nsec,
                          msg.idle_timeout, msg.hard_timeout,
                          msg.packet_count, msg.byte_count, msg.match)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        See https://osrg.github.io/ryu-book/en/html/switching_hub.html#event-handler for description.

        This function handles the ryu.controller.handler.MAIN_DISPATCHER state. This state is used to handle a new
        inbound packet

        :param ev: The event containing the packet data.
        """

        msg = ev.msg
        datapath = msg.datapath

        # Same as ofproto, indicates the ofproto_parser module. In the case of OpenFlow 1.3 format will be following
        # module. ryu.ofproto.ofproto_v1_3_parser
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id  # 64-bit OpenFlow Datapath ID of the switch to which the port belongs.

        # Get the OpenFlow protocol in use.
        ofproto = datapath.ofproto

        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)


class RyuRest(RyuController, RestStatsApi):
    """
    Overview is here: https://osrg.github.io/ryu-book/en/html/rest_api.html

    This class extends the RyuController class above in order to add a REST API functionality.

    """

    # A dictionary to specify contexts which this Ryu application wants to use. Its key is a name of context and its
    # value is an ordinary class which implements the context. The class is instantiated by app_manager and the instance
    # is shared among RyuApp subclasses which has _CONTEXTS member with the same key. A RyuApp subclass can obtain a
    # reference to the instance via its __init__'s kwargs as the following.
    # Class variable _CONTEXT is used to specify Ryu’s WSGI-compatible Web server class. By doing so, WSGI’s Web server
    # instance can be acquired by a key called the wsgi key.
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'dpset': dpset.DPSet
    }

    def __init__(self, *args, **kwargs):
        self.switches = {}
        wsgi = kwargs['wsgi']

        # For registration, the register method is used. When executing the register method, the dictionary object is
        # passed in the key name ryu_app so that the constructor of the controller can access the instance
        # of the RyuRest class.
        wsgi.register(RyuRestServer, {ryu_instance: self})
        RyuController.__init__(self, *args, **kwargs)
        RestStatsApi.__init__(self, *args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Parent class switch_features_handler is overridden. This method, upon rising of the SwitchFeatures event,
        acquires the datapath object stored in event object ev and stores it in instance variable switches. Also, at
        this time, an empty dictionary is set as the initial value in the MAC address table.

        :param ev: The switch event object containing the message data For this function we expect an instance of
                   ryu.ofproto.ofproto_v1_3_parser.OFPSwitchFeatures
        :return:
        """

        super(RyuRest, self).switch_features_handler(ev)  # Call the original switch features method
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

    def get_datapath(self, dpid: int) -> Datapath:
        """
        Allows you to retrieve the Datapath for a switch with the associated DPID

        :param dpid: The dpid you want to retrieve.
        :return: a Datapath object representing the given switch or None if it is not found.
        """

        return self.switches.get(dpid, None)


class RyuRestServer(StatsController):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'dpset': dpset.DPSet
    }

    def __init__(self, req, link, data, **config):
        data["dpset"] = data[ryu_instance].dpset

        # waiters in this case is ultimately used by ofctl_utils.py. It appears to be used for locks
        data["waiters"] = {}
        super(RyuRestServer, self).__init__(req, link, data, **config)
        self.ryu_app = data[ryu_instance]

    # TODO - I used half a bracket on path. If you add the other half it breaks. Did I just accidentally hack webobs?
    # TODO - It probably shouldn't work like this.
    @route('/gelante', '/gelante/ryuapi/{path', methods=['GET', 'PUT'])
    def ryuapi(self, req: json, **kwargs) -> Response:

        http = urllib3.PoolManager()

        response = http.request('GET', 'http://127.0.0.1:8080/' + kwargs["path"])

        return Response(content_type='application/json', text=response.body)


def main():
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6633')  # The port on which you want the controller to listen.
    sys.argv.append('main')  # This is the name of the Ryu app
    sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    manager.main()


if __name__ == '__main__':
    main()
