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

    info( '\n*** Adding remote controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6653)

    info( '\n*** Add switches\n')
    s1 = net.addSwitch('s1', dpid='0000000000000001')
    s2 = net.addSwitch('s2', dpid='0000000000000002')
    s3 = net.addSwitch('s3', dpid='0000000000000003')
    s4 = net.addSwitch('s4', dpid='0000000000000004')

    info( '\n*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.2/24', mac='00:00:00:00:00:01', defaultRoute='via 10.0.0.1')
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.3/24', mac='00:00:00:00:00:02', defaultRoute='via 10.0.0.1')
    h3 = net.addHost('h3', cls=Host, ip='11.0.0.2/24', mac='00:00:00:00:00:03', defaultRoute='via 11.0.0.1')
    h4 = net.addHost('h4', cls=Host, ip='192.168.1.2/24', mac='00:00:00:00:00:04', defaultRoute='via 192.168.1.1')
    h5 = net.addHost('h5', cls=Host, ip='10.8.1.2/24', mac='00:00:00:00:00:05', defaultRoute='via 10.8.1.1')

    info( '\n*** Add links\n')
    net.addLink(h1, s1, port1=1, port2=1, bw=100, delay='0.05')
    net.addLink(h2, s1, port1=1, port2=2, bw=100, delay='0.05')
    net.addLink(h3, s4, port1=1, port2=1, bw=1, delay='0.5')
    net.addLink(h4, s2, port1=1, port2=1, bw=100, delay='0.05')
    net.addLink(h5, s3, port1=1, port2=1, bw=100, delay='0.05')

    net.addLink(s1, s2, port1=3, port2=2, bw=1, delay='2')
    net.addLink(s2, s3, port1=3, port2=2, bw=5, delay='2')
    net.addLink(s3, s4, port1=3, port2=2, bw=20, delay='2')

    info( '\n*** Starting network\n')
    net.start()

    # Forcing OpenFlow13
    for sw_name in ['s1','s2','s3','s4']:
        sw = net.get(sw_name)
        sw.cmd(f'ovs-vsctl set Bridge {sw.name} protocols=OpenFlow13')

    info( '\n*** Starting iperf servers on all hosts\n')

    for host in net.hosts:
        info(f' *** Starting iperf server on {host.name}\n')
        # Server TCP iperf su porta 5001
        host.cmd(f'iperf -s -y C -p 5001 >> "Logs/{host.name}_tcp_log.csv" 2>&1 &')
        # Server UDP iperf su porta 5002
        host.cmd(f'iperf -s -u -y C -p 5002 >> "Logs/{host.name}_udp_log.csv" 2>&1 &')

    info('\n*** Starting Flask server on h1\n')
    h1 = net.get('h1')
    h1.cmd('python h1_server.py &')

    info( '\n***Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

