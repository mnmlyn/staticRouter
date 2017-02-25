#coding=utf-8

"""
My custom topology
根据Mininet wiki中Router Exercise部分中的拓扑图创建拓扑。
此为定制拓扑文件，使用方法参见Mininet的--custom与--topo属性
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        host1_1 = self.addHost( 'h1_1', ip = "10.0.1.101/24", defaultRoute = "via 10.0.1.1" )
        host1_2 = self.addHost( 'h1_2', ip = "10.0.1.102/24", defaultRoute = "via 10.0.1.1" )
        host1_3 = self.addHost( 'h1_3', ip = "10.0.1.103/24", defaultRoute = "via 10.0.1.1" )
        host2 = self.addHost( 'h2', ip = "10.0.2.100/24", defaultRoute = "via 10.0.2.1" )
        host3 = self.addHost( 'h3', ip = "10.0.3.100/24", defaultRoute = "via 10.0.3.1" )
        router1 = self.addSwitch( 'r1' )
        switch2 = self.addSwitch( 's2' )

        # Add links
        self.addLink( host1_1, switch2 )
        self.addLink( host1_2, switch2 )
        self.addLink( host1_3, switch2 )
        # Add links
        self.addLink( switch2, router1 )
        self.addLink( host2, router1 )
        self.addLink( host3, router1 )

topos = { 'mytopo': ( lambda: MyTopo() ) }
