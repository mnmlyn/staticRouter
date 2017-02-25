# coding=utf-8
# 编写一个简单控制器程序，实现静态路由器功能
# 对主机发来的arp请求进行回应
# 按照静态路由表进行ip层的转发
# 回应对于路由器本身的icmp echo请求
# 对于未能匹配路由表的ip包，发送icmp网络不可达报文

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.openflow.libopenflow_01 import *
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet import ethernet
from pox.lib.packet.ethernet import ETHER_ANY, ETHER_BROADCAST
from pox.lib.packet import arp, ipv4, icmp
from pox.lib.packet.icmp import TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY,\
                                 TYPE_DEST_UNREACH, CODE_UNREACH_NET, CODE_UNREACH_HOST

log = core.getLogger()

# arp映射表
# 结构为{ dpid1:{ port_no1:{ ip1:mac1 , ip1:mac2 , ... } , port_no2:{ ... } , ... } , dpid2:{ ... } , ... }
arpTable = {}
# 端口映射表
# 结构为{ dpid : [ [ port_no1 , mac1 , ip1 ] , [ port_no2 , mac2 , ip2 ] , dpid2 : ... ] }
portTable = {}

# 路由表常量
# 结构为：[ [ 网络 , 下一跳ip地址 , 下一跳接口名称 , 下一跳接口ip , 下一跳端口 ] , [ ... ] , ... ]
rDST_NETWORK = 0
rNEXTHOP_IP = 1
rNEXTHOP_PORT_NAME = 2
rNEXTHOP_PORT_IP = 3
rNEXTHOP_PORT = 4

# 端口映射表常量
# 记录路由器本身端口、ip与mac映射
# 结构为{ dpid : [ [ port_no1 , mac1 , ip1 ] , [ port_no2 , mac2 , ip2 ] , dpid2 : ... ] }
pPORT = 0
pPORT_MAC = 1
pPORT_IP = 2

class routerConnection(object):

  def __init__(self,connection):
    dpid = connection.dpid
    log.debug('-' * 50 + "dpid=" + str(dpid) + '-' * 50)
    log.debug('-' * 50 + "I\'m a StaticRouter" + '-' * 50)

    # 初始化arp映射表
    arpTable[dpid] = {}
    # 初始化端口映射表
    portTable[dpid] = []

    #根据features_reply包来生成arp表和端口映射表
    for entry in connection.ports.values():
      port = entry.port_no
      mac = entry.hw_addr
      #对路由器与控制器端口不生成arp表
      if port <= of.ofp_port_rev_map['OFPP_MAX']:
        arpTable[dpid][port] = {}
        if port == 1:
          ip = IPAddr('10.0.1.1')
          arpTable[dpid][port][ip] = mac
          portTable[dpid].append([port, mac, ip])
        elif port == 2:
          ip = IPAddr('10.0.2.1')
          arpTable[dpid][port][ip] = mac
          portTable[dpid].append([port, mac, ip])
        elif port == 3:
          ip = IPAddr('10.0.3.1')
          arpTable[dpid][port][ip] = mac
          portTable[dpid].append([port, mac, ip])
        else:
          ip = IPAddr('0.0.0.0') # 未分配ip
          arpTable[dpid][port][ip] = mac
          portTable[dpid].append([port, mac, ip])

    # 打印arp表
    log.debug('-'*50 + 'arpTable' + '-'*50)
    log.debug(arpTable)

    # 打印端口映射表
    log.debug('-'*50 + 'portTable' + '-'*50)
    log.debug(portTable)

    # ip路由表
    # 结构为：[ [ 网络 , 下一跳ip地址 , 下一跳接口名称 , 下一跳接口ip , 下一跳端口 ] , [ ... ] , ... ]
    # 下一跳ip为0.0.0.0表示直接交付
    self.routeTable = []
    self.routeTable.append(['10.0.1.0/24',
                            '0.0.0.0', 's1-eth1', '10.0.1.1', 1])
    self.routeTable.append(['10.0.2.0/24',
                            '10.0.2.100', 's1-eth2', '10.0.2.1', 2])
    self.routeTable.append(['10.0.3.0/24',
                            '10.0.3.100', 's1-eth3', '10.0.3.1', 3])

    self.connection = connection
    connection.addListeners(self)

  # 流删除消息
  def _handle_FlowRemoved(self,event):
    dpid = event.connection.dpid
    log.debug('-' * 50 + "dpid=" + str(dpid) + '-' * 50)
    log.debug('A FlowRemoved Message Recieved')
    log.debug('---A flow has been removed')

  # PackerIn消息
  def _handle_PacketIn(self,event):
    dpid = self.connection.dpid
    log.debug('-' * 50 + "dpid=" + str(dpid) + '-' * 50)
    log.debug("A PacketIn Message Recieved")
    packet = event.parsed

    # arp
    if packet.type == ethernet.ARP_TYPE:
      log.debug('---It\'s an arp packet')
      arppacket = packet.payload
      # arp回应
      if arppacket.opcode == arp.REPLY:
        arpTable[self.connection.dpid][event.ofp.in_port][arppacket.protosrc] = arppacket.hwsrc
        arpTable[self.connection.dpid][event.ofp.in_port][arppacket.protodst] = arppacket.hwdst
        # 更新后的arp表
        log.debug('------arpTable learned form arp Reply srt and dst')
        log.debug('------' + str(arpTable))

      # arp请求
      if arppacket.opcode == arp.REQUEST:
        log.debug('------Arp request')
        log.debug('------' + arppacket._to_str())
        arpTable[self.connection.dpid][event.ofp.in_port][arppacket.protosrc] = arppacket.hwsrc
        # 更新后的arp表
        log.debug('------arpTable learned form arp Request srt')
        log.debug('------' + str(arpTable))

        # 发送arp回应
        if arppacket.protodst in arpTable[self.connection.dpid][event.ofp.in_port]:
          log.debug('------I know that ip %s,send reply'%arppacket.protodst)

          #构造arp回应
          a = arppacket
          r = arp()
          r.hwtype = a.hwtype
          r.prototype = a.prototype
          r.hwlen = a.hwlen
          r.protolen = a.protolen
          r.opcode = arp.REPLY
          r.hwdst = a.hwsrc
          r.protodst = a.protosrc
          r.protosrc = a.protodst
          r.hwsrc = arpTable[self.connection.dpid][event.ofp.in_port][arppacket.protodst]
          e = ethernet(type=packet.type, src=r.hwsrc,dst=a.hwsrc)
          e.set_payload(r)
          msg = of.ofp_packet_out()
          msg.data = e.pack()
          msg.actions.append(of.ofp_action_output(port=event.ofp.in_port))
          self.connection.send(msg)

    # ip包
    if packet.type == ethernet.IP_TYPE:
      log.debug('---It\'s an ip packet')
      ippacket = packet.payload
      # 目的ip
      dstip = ippacket.dstip

      # 查找端口映射表，判断目的ip是否为路由器本身,回应icmp echo reply
      for t in portTable[dpid]:
        selfip = t[pPORT_IP]
        # 如果目的ip地址为当前路由器拥有的地址
        if dstip == selfip:
          #如果是icmp echo request报文
          if ippacket.protocol == ipv4.ICMP_PROTOCOL:
            log.debug('!!!!!!!!!!An icmp for me!!!!!!!!!!!')
            icmppacket = ippacket.payload
            #是否为icmp echo request
            if icmppacket.type == TYPE_ECHO_REQUEST:
              selfmac = t[pPORT_MAC]
              log.debug('!!!!!!!!!!An icmp echo request for me!!!!!!!!!!!')

              # 构造icmp包
              r = icmppacket
              r.type = TYPE_ECHO_REPLY

              #构造ip包
              s = ipv4()
              s.protocol = ipv4.ICMP_PROTOCOL
              s.srcip = selfip
              s.dstip = ippacket.srcip
              s.payload = r

              #构造以太网帧
              e = ethernet()
              e.type = ethernet.IP_TYPE
              e.src = selfmac
              e.dst = packet.src
              e.payload = s

              # 构造PacketOut消息
              # 回发icmp包
              msg = of.ofp_packet_out()
              msg.data = e.pack()
              msg.actions.append(of.ofp_action_output(port=event.port))
              self.connection.send(msg)
              log.debug('!!!!!!!!!!Reply it!!!!!!!!!!!')
              return
            else:
              #对发往路由器的icmp包，除了icmp echo request之外，均不理会
              return
          #发往路由器的非icmp包
          else:
            #直接丢包，这里控制器暂时不做回应
            return

      # 搜索路由表
      for t in self.routeTable:
        # 路由表项中的网络前缀
        dstnetwork = t[rDST_NETWORK]
        # 如果目的ip在路由表中
        if dstip.inNetwork(dstnetwork):
          log.debug('------ip dst %s is in the routeTable' % dstip)

          # 找到对应的下一跳信息
          nh_port = t[rNEXTHOP_PORT]
          if nh_port == event.ofp.in_port:
            return# 应该下达丢包动作
          nh_ip = IPAddr(t[rNEXTHOP_IP])
          # 直接交付
          if nh_ip == IPAddr('0.0.0.0'):
            nh_ip = dstip
          nh_port_ip = IPAddr(t[rNEXTHOP_PORT_IP])

          # 查找arp表
          nh_mac_src = arpTable[dpid][nh_port][nh_port_ip]

          # 若下一跳目的主机的mac已知，添加流表
          if nh_ip in arpTable[dpid][nh_port]:
            log.debug('------I know the next dst %s mac' % nh_ip)
            nh_mac_dst = arpTable[dpid][nh_port][nh_ip]

            # 下发流表
            msg1 = of.ofp_flow_mod()
            # 匹配
            msg1.match = of.ofp_match()
            msg1.match.dl_type = ethernet.IP_TYPE
            msg1.match.nw_dst = dstip
            # Flow actions
            msg1.command = 0
            msg1.idle_timeout = 10
            msg1.hard_timeout = 30
            msg1.buffer_id = event.ofp.buffer_id
            msg1.flags = 3  # of.ofp_flow_mod_flags_rev_map('OFPFF_CHECK_OVERLAP') | of.ofp_flow_mod_flags_rev_map('OFPFF_CHECK_OVERLAP')
            msg1.actions.append(of.ofp_action_dl_addr.set_src(nh_mac_src))
            msg1.actions.append(of.ofp_action_dl_addr.set_dst(nh_mac_dst))
            msg1.actions.append(of.ofp_action_output(port=nh_port))
            self.connection.send(msg1)
            log.debug('###Add a flow###')

          # 若下一跳目的主机的mac未知，发送arp请求，并广播ip包
          else:
            log.debug('------I don\'t know the next dst %s mac,make an arp request' % IPAddr(t[rNEXTHOP_IP]))
            # 构造arp请求
            r = arp()
            r.opcode = arp.REQUEST
            r.protosrc = nh_port_ip
            r.hwsrc = nh_mac_src
            r.protodst = nh_ip
            e_arp = ethernet(type=ethernet.ARP_TYPE, src=r.hwsrc, dst=ETHER_BROADCAST)
            e_arp.set_payload(r)
            msg = of.ofp_packet_out()
            msg.data = e_arp.pack()
            msg.actions.append(of.ofp_action_output(port=nh_port))
            msg.in_port = event.ofp.in_port
            event.connection.send(msg)

            # 广播ip包，不下发流表
            nh_mac_dst = ETHER_BROADCAST
            msg1 = of.ofp_packet_out()
            msg1.in_port = event.port
            msg1.buffer_id = event.ofp.buffer_id
            msg1.actions.append(of.ofp_action_dl_addr.set_src(nh_mac_src))
            msg1.actions.append(of.ofp_action_dl_addr.set_dst(nh_mac_dst))
            msg1.actions.append(of.ofp_action_output(port=nh_port))
            self.connection.send(msg1)

          return

      # 在路由表中未找到匹配项，发送icmp网络不可达报文
      r = icmp()
      r.type = TYPE_DEST_UNREACH
      r.code = CODE_UNREACH_NET
      d = ippacket.pack()[:ippacket.iplen + 8]
      import struct
      d = struct.pack("!I", 0) + d  #不可达报文的unused字段，也包含在icmp的payload中
                                    #这里大写的I代表4字节无符号整形，0代表数值，
                                    # struct.pack("!I", 0)的返回值是4个字节的0，正好填在不可达报文未用字段
      r.payload = d
      s = ipv4()
      s.protocol = ipv4.ICMP_PROTOCOL
      for t in portTable[dpid]:
        selfip = t[pPORT_IP]
        if(event.port == t[pPORT]):
          s.srcip = selfip
          break
      s.dstip = ippacket.srcip
      s.payload = r
      e = ethernet()
      e.type = ethernet.IP_TYPE
      e.src = packet.dst
      e.dst = packet.src
      e.payload = s

      # 构造PacketOut消息
      # 回发icmp包
      msg = of.ofp_packet_out()
      msg.data = e.pack()
      msg.actions.append(of.ofp_action_output(port=event.port))
      self.connection.send(msg)

class l2SwitchConnection(object):

  def __init__(self,connection):

    # dpid
    dpid = connection.dpid
    log.debug('-' * 50 + "dpid=" + str(dpid) + '-' * 50)
    log.debug('-' * 50 + "I\'m a L2switch" + '-' * 50)

    # mac到端口映射表
    self.macToPortTable = {}

    self.connection = connection
    connection.addListeners(self)

  # 流删除消息
  def _handle_FlowRemoved(self,event):
    dpid = event.connection.dpid
    log.debug('-' * 50 + "dpid=" + str(dpid) + '-' * 50)
    log.debug('A FlowRemoved Message Recieved')
    log.debug('---A flow has been removed')

  # PacketIn消息
  def _handle_PacketIn(self,event):
    dpid = event.connection.dpid
    log.debug('-' * 50 + "dpid=" + str(dpid) + '-' * 50)
    log.debug("A PacketIn Message Recieved")
    srcport = event.ofp.in_port
    log.debug('srcport=%s' % srcport)

    # 假定只有以太网帧，不考虑LLDP等
    packet = event.parsed
    srcmac = packet.src
    dstmac = packet.dst

    # 只从以太网帧的源mac中进行学习
    self.macToPortTable[srcmac] = srcport

    # 如果dstmac在mac到端口的映射表中
    if dstmac in self.macToPortTable and dstmac != ETHER_BROADCAST:
      log.debug('I know the mac\'s port')
      dstport = self.macToPortTable[dstmac]
      msg = of.ofp_flow_mod()
      msg.match.dl_dst = dstmac
      msg.command = of.ofp_flow_mod_command_rev_map['OFPFC_ADD']
      msg.idle_timeout = 30
      msg.hard_timeout = 60
      msg.buffer_id = event.ofp.buffer_id
      msg.actions.append(of.ofp_action_output(port=dstport))
      self.connection.send(msg)
    else:
      log.debug('I don\'t know the mac\'s port')
      dstport = of.ofp_port_rev_map['OFPP_FLOOD']
      msg = ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.actions.append(of.ofp_action_output(port=dstport))
      self.connection.send(msg)

class MyHubComponent(object):
  def __init__(self):
    core.openflow.addListeners(self)

  def _handle_ConnectionUp(self,event):
    dpid = event.connection.dpid
    log.debug('-' * 45 + "A Switch ConnectionUp!" + '-' * 50)
    if dpid == 1:
      routerConnection(event.connection)
    elif dpid == 2:
      l2SwitchConnection(event.connection)

  def _handle_ConnectionDown(self,event):
    dpid = event.connection.dpid
    # 在交换机断开时，删除相应的表项
    try:
      arpTable.pop(dpid)
      log.debug('Remove a arpTable of dpid %s' % dpid)
      portTable.pop(dpid)
      log.debug('Remove a portTable of dpid %s' % dpid)
    except:
      pass

def launch():
  core.registerNew(MyHubComponent)

