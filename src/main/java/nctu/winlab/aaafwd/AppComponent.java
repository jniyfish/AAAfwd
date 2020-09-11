/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.aaafwd;


//import org.onosproject.core.ApplicationId;
//import org.onosproject.core.CoreService;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.opencord.aaa.AaaMachineStatisticsService;
import org.opencord.aaa.AuthenticationService;
import org.opencord.aaa.AuthenticationRecord;
import org.opencord.aaa.AuthenticationEvent;
import org.opencord.aaa.AuthenticationEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.core.CoreService;
import static org.onlab.util.Tools.get;
//import java.util.List;
import java.util.Set;
import java.util.LinkedList;
import org.onlab.packet.MacAddress;
import org.onlab.packet.Ethernet;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.Path;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.host.HostService;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onlab.packet.ICMP;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Prefix;
//import org.onlab.packet.Ip4Address;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true, service = { SomeInterface.class }, property = {
        "someProperty=Some Default String Value", })
public class AppComponent implements SomeInterface {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private ApplicationId appId;
    /** Some configurable property. */
    private String someProperty;
    /** Configure Flow Timeout for installed flow rules; default is 20 sec.*/
    private int flowTimeout = 20;

    /** Configure Flow Priority for installed flow rules; default is 40001.*/
    private int flowPriority = 40001;
    private String gatewayMac = "ea:e9:78:fb:fd:00";

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected AaaMachineStatisticsService aaaMachineStatsManager;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected AuthenticationService aaaManager;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(), context.inPacket().receivedFrom())) {
            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private final AuthenticationEventListener authenticationEventHandler = new InternalAuthenticationEventListener();
    private LinkedList<MacAddress> authorrizedHost = new LinkedList<MacAddress>();
    private void normalPkt(PacketContext context) {

        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();

        HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
        Host dst = hostService.getHost(dstId);

        if (dst == null) {
            flood(context);
            return;
        }

        if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
            if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                installRule(context, dst.location().port());
            }
            return;
        }

        Path path = calculatePath(context);

        if (path == null) {
            flood(context);
            return;
        }
        log.info("installrule");
        installRule(context, path.src().port());
    }
    private boolean isSpecificLayer4Port(Integer portNum) {

        if (portNum == 53 || portNum == 443 || portNum == 80) {
            return true;
        }
        return false;
    }
    private boolean isMyLocalAreaNetwork(Ip4Prefix addr) {
        if (addr.toString().equals("192.168.44.0/24")) {
            return true;
        }
        return false;
    }
    private void installRule(PacketContext context, PortNumber portNumber) {
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        // Forward ARP packets directly to output port
        if (inPkt.getEtherType() == Ethernet.TYPE_ARP) {
            packetOut(context, portNumber);
            return;
        }

        selectorBuilder.matchInPort(context.inPacket().receivedFrom().port());

        if (inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
            IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
            byte ipv4Protocol = ipv4Packet.getProtocol();
            Ip4Prefix matchIp4SrcPrefix = Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(), Ip4Prefix.MAX_MASK_LENGTH);
            Ip4Prefix matchIp4DstPrefix = Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                    Ip4Prefix.MAX_MASK_LENGTH);
            selectorBuilder.matchEthType(Ethernet.TYPE_IPV4);
            if (isMyLocalAreaNetwork(Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(), 24))) {
                selectorBuilder.matchIPSrc(matchIp4SrcPrefix);
            }
            if (isMyLocalAreaNetwork(Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(), 24))) {
                selectorBuilder.matchIPDst(matchIp4DstPrefix);
            }
            if (ipv4Protocol == IPv4.PROTOCOL_TCP) {
                TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol);
                if (isSpecificLayer4Port(tcpPacket.getSourcePort())) {
                    selectorBuilder.matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()));
                }
                if (isSpecificLayer4Port(tcpPacket.getDestinationPort())) {
                    selectorBuilder.matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                }
            }
            if (ipv4Protocol == IPv4.PROTOCOL_UDP) {
                UDP udpPacket = (UDP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol);
                if (isSpecificLayer4Port(udpPacket.getSourcePort())) {
                    selectorBuilder.matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()));
                }
                if (isSpecificLayer4Port(udpPacket.getDestinationPort())) {
                    selectorBuilder.matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                }
            }
            if (ipv4Protocol == IPv4.PROTOCOL_ICMP) {
                ICMP icmpPacket = (ICMP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol);
            }
        }

        TrafficTreatment.Builder treatmentBuilder = DefaultTrafficTreatment.builder();
        treatmentBuilder.setOutput(portNumber);

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build()).withTreatment(treatmentBuilder.build())
                .withPriority(flowPriority).withFlag(ForwardingObjective.Flag.VERSATILE).fromApp(appId)
                .makeTemporary(flowTimeout).add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);

        packetOut(context, portNumber);
    }
    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            log.info("debug");
            if (context.isHandled()) {
                return;
            }
            int intDstPort;
            int intSrcPort;
            String sourcePort = "";
            String destinationPort = "";

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
            byte protocol = ipv4Packet.getProtocol(); 
            if (protocol == IPv4.PROTOCOL_TCP) {
                TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                intSrcPort = tcpPacket.getSourcePort();
                intDstPort = tcpPacket.getDestinationPort();
                sourcePort = PortNumber.portNumber(Integer.toString(intSrcPort)).toString();
                destinationPort = PortNumber.portNumber(Integer.toString(intDstPort)).toString();
            } else if (protocol == IPv4.PROTOCOL_UDP) {
                UDP udpPacket = (UDP) ipv4Packet.getPayload();
                intSrcPort = udpPacket.getSourcePort();
                intDstPort = udpPacket.getDestinationPort();
                sourcePort = PortNumber.portNumber(Integer.toString(intSrcPort)).toString();
                destinationPort = PortNumber.portNumber(Integer.toString(intDstPort)).toString();
            }

            if (ethPkt == null) {
                return;
            }
            if (protocol == IPv4.PROTOCOL_UDP) {
                if ((sourcePort.equals("67") && destinationPort.equals("68")) ||
                (sourcePort.equals("68") && destinationPort.equals("67"))) {
                    normalPkt(context);
                    return;
                }
            }

             // Pass DNS packets
            if (protocol == IPv4.PROTOCOL_UDP || protocol == IPv4.PROTOCOL_TCP) {
                if ((sourcePort.equals("53") || destinationPort.equals("53"))) {
                    normalPkt(context);
                    return;
                }
            }
            // Pass ICMP packets
            if (protocol == IPv4.PROTOCOL_ICMP) {
                normalPkt(context);
                return;
            }
            if (protocol == IPv4.PROTOCOL_TCP) {
                // Pass any packets that its destination is portal or from gateway
                if (ethPkt.getSourceMAC().toString().equalsIgnoreCase(gatewayMac)) {
                    normalPkt(context);
                    return;
                }
                if (authorrizedHost.contains(ethPkt.getSourceMAC())
                    || authorrizedHost.contains(ethPkt.getDestinationMAC())) {
                    log.info("Authorized`");
                    normalPkt(context);
                } else {
                    log.info("Didnt authorized, src mac: " + ethPkt.getSourceMAC().toString()
                    + "dst mac: " + ethPkt.getDestinationMAC().toString());
                }
            }
        }

    }
    private class InternalAuthenticationEventListener implements AuthenticationEventListener {
        @Override
        public void event(AuthenticationEvent event) {
            log.info("I hear something from AuthenticationEventListener. ");
            AuthenticationRecord aaaAuthenticationRecord = event.authenticationRecord();
            log.info("**SupplicantMacAddress: " + aaaAuthenticationRecord.supplicantAddress().toString());
            log.info("**ConnectPoint: " + aaaAuthenticationRecord.supplicantConnectPoint().toString());
            log.info("**userName: " + new String(aaaAuthenticationRecord.username()));
            log.info("**state: " + aaaAuthenticationRecord.state());
            if (aaaAuthenticationRecord.state().toString().equals("AUTHORIZED_STATE")) {
                authorrizedHost.add(aaaAuthenticationRecord.supplicantAddress());
                log.info(aaaAuthenticationRecord.state().toString());
            }
        }
    }
    private Path calculatePath(PacketContext context) {
        InboundPacket inPkt = context.inPacket();
        Ethernet ethPkt = inPkt.parsed();

        HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
        Host dst = hostService.getHost(dstId);
        log.info(inPkt.receivedFrom().deviceId().toString());
        Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(), inPkt.receivedFrom().deviceId(),
                dst.location().deviceId());
        if (paths.isEmpty()) {
            log.info("Path is empty when calculate Path");
            return null;
        }

        Path path = pickForwardPathIfPossible(paths, inPkt.receivedFrom().port());
        if (path == null) {
            log.warn("Don't know where to go from here {} for {} -> {}", inPkt.receivedFrom(), ethPkt.getSourceMAC(),
                    ethPkt.getDestinationMAC());
            return null;
        } else {
            return path;
        }
    }
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        Path lastPath = null;
        for (Path path : paths) {
            lastPath = path;
            if (!path.src().port().equals(notToPort)) {
                return path;
            }
        }
        return lastPath;
    }
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("nctu.winlab.aaafwd");
        log.info("Started");
        aaaManager.addListener(authenticationEventHandler);
        packetService.addProcessor(processor, PacketProcessor.director(2));
        requestIntercepts();
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        aaaManager.removeListener(authenticationEventHandler);
        packetService.removeProcessor(processor);
        withdrawIntercepts();
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

}

