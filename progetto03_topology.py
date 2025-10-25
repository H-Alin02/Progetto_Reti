from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                    build=False,
                    ipBase='10.0.0.0/8',
                    link=TCLink,
                    switch=OVSKernelSwitch )

    info( '*** Adding remote controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6653)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', dpid='0000000000000001')
    s2 = net.addSwitch('s2', dpid='0000000000000002')
    s3 = net.addSwitch('s3', dpid='0000000000000003')
    s4 = net.addSwitch('s4', dpid='0000000000000004')

    info( '*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.2/24', defaultRoute='via 10.0.0.1')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.3/24', defaultRoute='via 10.0.0.1')
    h3 = net.addHost('h3', cls=Host, ip='11.0.0.2/24', defaultRoute='via 11.0.0.1')
    h4 = net.addHost('h4', cls=Host, ip='192.168.1.2/24', defaultRoute='via 192.168.1.1')
    h5 = net.addHost('h5', cls=Host, ip='10.8.1.2/24', defaultRoute='via 10.8.1.1')

    info( '*** Add links\n')
    h1s1 = {'bw':100,'delay':'0.05'}
    net.addLink(h1, s1, cls=TCLink , **h1s1)
    h2s1 = {'bw':100,'delay':'0.05'}
    net.addLink(h2, s1, cls=TCLink , **h2s1)
    h3s4 = {'bw':1,'delay':'0.5'}
    net.addLink(h3, s4, cls=TCLink , **h3s4)
    h5s3 = {'bw':100,'delay':'0.05'}
    net.addLink(h5, s3, cls=TCLink , **h5s3)
    h4s2 = {'bw':100,'delay':'0.05'}
    net.addLink(h4, s2, cls=TCLink , **h4s2)
    s1s2 = {'bw':1,'delay':'2'}
    net.addLink(s1, s2, cls=TCLink , **s1s2)
    s2s3 = {'bw':5,'delay':'2'}
    net.addLink(s2, s3, cls=TCLink , **s2s3)
    s3s4 = {'bw':20,'delay':'2'}
    net.addLink(s3, s4, cls=TCLink , **s3s4)

    info( '*** Starting network\n')
    net.build()

    info( '*** Starting controllers\n')
    c0.start()
    
    info( '*** Starting switches\n')
    net.get('s1').start([])
    net.get('s2').start([])
    net.get('s3').start([])
    net.get('s4').start([])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

