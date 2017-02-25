# staticRouter
基于Mininet对SDN/OpenFlow网络进行仿真，搭建了由一个三层路由器staticRouter、一个二层自学习交换机以及若干台主机构成的网络拓扑。使用POX做控制器，编程实现了网络中各个主机之间的连通性。
其中mytopo.py文件为Mininet的定制拓扑文件。
在文件所在路径执行$ sudo mn --custom mytopo.py --topo mytopo即可启动拓扑
staticRouter.py文件为POX中的控制器模块，应存放在POX的ext文件夹下
启动控制器方法为$ ./pox.py log.level --DEBUG staticRouter
