# Nmap主机发现源码分析

## 主机发现流程

主机发现主体是nmap_main()函数中的nexthost()函数，nexthost()函数中主要分为两个阶段：地址解析和探测。地址解析负责从主机表达式中解析出目标主机地址存放在hostbatch中并配置相关路由、网口等信息；探测负责对解析出来的目标主机进行实际探测。

**地址解析**：

1. 查看当前batch中是否有已解析的主机，如果有则返回batch中的下一个主机；如果没有则进行下一步
2. 若当前的batch没有占满且主机表达式没有解析完毕，则先对主机表达式进行解析
3. 从当前主机表达式中获取主机地址(跳过被排出的地址)
4. 若当前地址已被转换，则设置其域名以及地址并获得其源IP以及设备信息
5. 如果改地址不需要新的分组，则重复2-5直到batch占满且主机表达式解析完毕；如果地址需要新的分组则取消对当前地址操作，开始进行主机发现过程

**探测**：

1. 检查当前batch是否为空
2. 对batch内主机进行随机打乱
3. 对以太网内主机进行ARP探测
4. 若用户指定列表扫描或无需ping，则标记该主机在线
5. 使用mass ping进行探测(ICMP echo,TCP SYN,TCP ACK,ICMP time stamp)
6. 进行rdns解析
7. 返回主机发现后第一个主机地址

## 基本信息定义

### 主机组

```c
class HostGroupState {
 public:
  HostGroupState(int lookahead, int randomize, char *target_expressions[],
		 int num_expressions);
  ~HostGroupState();
  Target **hostbatch;
  int max_batch_sz; /* The size of the hostbatch[] array */
  int current_batch_sz; /* The number of VALID members of hostbatch[] */
  int next_batch_no; /* The index of the next hostbatch[] member to be given 
			back to the user */
  int randomize; /* Whether each batch should be "shuffled" prior to the ping 
		    scan (they will also be out of order when given back one
		    at a time to the client program */
  char **target_expressions; /* An array of target expression strings, passed
				to us by the client (client is also in charge
				of deleting it AFTER it is done with the 
				hostgroup_state */
  int num_expressions;       /* The number of valid expressions in 
				target_expressions member above */
  int next_expression;   /* The index of the next expression we have
			    to handle */
  TargetGroup current_expression; /* For batch chunking -- targets in queue */
};
```

主机组类中定义了batch的最大大小、当前大小等信息。主机组类定义的对象代表当前batch。

### scan_list

```c
/* The various kinds of port/protocol scans we can have
 * Each element is to point to an array of port/protocol numbers
 */
struct scan_lists {
	/* The "synprobes" are also used when doing a connect() ping */
	unsigned short *syn_ping_ports;
	unsigned short *ack_ping_ports;
	unsigned short *udp_ping_ports;
	unsigned short *sctp_ping_ports;
	unsigned short *proto_ping_ports;
	int syn_ping_count;
	int ack_ping_count;
	int udp_ping_count;
	int sctp_ping_count;
	int proto_ping_count;
	//the above fields are only used for host discovery
	//the fields below are only used for port scanning
	unsigned short *tcp_ports;
	int tcp_count;
	unsigned short *udp_ports;
	int udp_count;
	unsigned short *sctp_ports;
	int sctp_count;
	unsigned short *prots;
	int prot_count;
};
```

scan_list中定义了端口/协议扫描的方式

## 地址解析

**批量处理**

加快主机发现速率，默认每4096个地址为一个batch。

**从主机表达式获取目标主机地址**

主机表达式：Nmap用于管理主机的方式。Nmap通过解析表达式得到IP具体是多少。

```c
Target *nexthost(HostGroupState *hs, const addrset *exclude_group,
                 struct scan_lists *ports, int pingtype) {
  int i;
  struct sockaddr_storage ss;
  size_t sslen;
  struct route_nfo rnfo;
  bool arpping_done = false;
  struct timeval now;
  ///当已经批量地探测一组主机，并将主机缓存在hostbatch中时，直接返回该主机对象指针即可
  if (hs->next_batch_no < hs->current_batch_sz) {
    /* Woop!  This is easy -- we just pass back the next host struct */
    return hs->hostbatch[hs->next_batch_no++];
  }
  /* Doh, we need to refresh our array */
  /* for (i=0; i < hs->max_batch_sz; i++) hs->hostbatch[i] = new Target(); */
  ///进行新一批的主机探测，以下do{}while(1)循环是先产生各个IP的主机对象并放入hostbatch[]中
  ///真正确定主机是否在线，是在batchfull:代码段内
  hs->current_batch_sz = hs->next_batch_no = 0;
```

**设置已转换地址**

若该地址已经被转换解析，则设置该地址对应的转换的地址或名字并记录转换地址列表。

```c
/* Grab anything we have in our current_expression */
    while (hs->current_batch_sz < hs->max_batch_sz && 
        hs->current_expression.get_next_host(&ss, &sslen) == 0) {
      Target *t;
      ///以下跳过被排除地址
      if (hostInExclude((struct sockaddr *)&ss, sslen, exclude_group)) {
        continue; /* Skip any hosts the user asked to exclude */
      }
      t = new Target();
      t->setTargetSockAddr(&ss, sslen);
 
      /* Special handling for the resolved address (for example whatever
         scanme.nmap.org resolves to in scanme.nmap.org/24). */
      if (hs->current_expression.is_resolved_address(&ss)) {
        if (hs->current_expression.get_namedhost())
          t->setTargetName(hs->current_expression.get_resolved_name());
        t->resolved_addrs = hs->current_expression.get_resolved_addrs();
      }
```

**获取源IP与网络设备**

进行路由信息查询，调用nmap_route_dst()函数。根据目的地址与查询的路由表对表决定采用哪个网卡发送数据包等信息。

```c
 /* We figure out the source IP/device IFF
         1) We are r00t AND
         2) We are doing tcp or udp pingscan OR
         3) We are doing a raw-mode portscan or osscan or traceroute OR
         4) We are on windows and doing ICMP ping */
      if (o.isr00t && 
          ((pingtype & (PINGTYPE_TCP|PINGTYPE_UDP|PINGTYPE_SCTP_INIT|PINGTYPE_PROTO|PINGTYPE_ARP)) || o.RawScan()
#ifdef WIN32
           || (pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS))
#endif // WIN32
          )) {
        t->TargetSockAddr(&ss, &sslen);
        if (!nmap_route_dst(&ss, &rnfo)) {
          fatal("%s: failed to determine route to %s", __func__, t->NameIP());
        }
        if (rnfo.direct_connect) {
          t->setDirectlyConnected(true);
        } else {
          t->setDirectlyConnected(false);
          t->setNextHop(&rnfo.nexthop, sizeof(rnfo.nexthop));
        }
        t->setIfType(rnfo.ii.device_type);
        if (rnfo.ii.device_type == devt_ethernet) {
          if (o.spoofMACAddress())
            t->setSrcMACAddress(o.spoofMACAddress());
          else
            t->setSrcMACAddress(rnfo.ii.mac);
        }
        t->setSourceSockAddr(&rnfo.srcaddr, sizeof(rnfo.srcaddr));
        if (hs->current_batch_sz == 0) /* Because later ones can have different src addy and be cut off group */
          o.decoys[o.decoyturn] = t->v4source();
        t->setDeviceNames(rnfo.ii.devname, rnfo.ii.devfullname);
        t->setMTU(rnfo.ii.mtu);
        // printf("Target %s %s directly connected, goes through local iface %s, which %s ethernet\n", t->NameIP(), t->directlyConnected()? "IS" : "IS NOT", t->deviceName(), (t->ifType() == devt_ethernet)? "IS" : "IS NOT");
      }
```

**判断是否重新划分批次**

如果新发现的主机与本次batch中其他主机差别较大，则在进行主机发现时可能会降低性能。因此需要检查目标是否需要新的批次：

* 地址类型不同
* 网卡不同
* 需要不同IP地址
* 目标主机与源主机直接相连而其他主机不直接相连
* 目标主机IP地址与当前批次其他目标机相同

```cc
	/* Does this target need to go in a separate host group? */
  if (target_needs_new_hostgroup(hs, t)) {
    /* Cancel everything!  This guy must go in the next group and we are
             out of here */
    hs->current_expression.return_last_host();
    delete t;
    goto batchfull;
  }

  hs->hostbatch[hs->current_batch_sz++] = t;
}
```

**更换主机表达式**

若当前主机表达式获取完毕目标主机，允许最大目标主机数量还未达到，则更换下一个主机表达式继续解析目标主机地址。

## 探测

**检查批次是否为空**

若无法找到有效目标地址，则该批次可能为空。

**随机打乱**

如果用户在使用命令时加上`--randomize-hosts`，那么对目标地址进行探测时需要打乱顺序执行。

```c
batchfull:
  if (hs->current_batch_sz == 0)///没有解析出有效地址，返回NULL
    return NULL;
 
  /* OK, now we have our complete batch of entries.  The next step is to
     randomize them (if requested) */
  if (hs->randomize) {  ///若命令行指定randomize-hosts选项，那么将目标地址随机打乱
    hoststructfry(hs->hostbatch, hs->current_batch_sz);
  }
```

**ARP探测**

当前batch内的所有目标主机都在源主机所在的以太网内，且用户没有指定—send-ip选项，那么采用ARP REQUEST的数据包探测所有目标主机是否在线。

```c
/* First I'll do the ARP ping if all of the machines in the group are
     directly connected over ethernet.  I may need the MAC addresses
     later anyway. */
  ///探测方式1：主机组内所有IP地址都直连在ethernet内，那么进行ARP PING报文探测
  ///向局域网广播:ARP REQUEST包，询问谁持有xx.xx.xx.xxIP地址
  if (hs->hostbatch[0]->ifType() == devt_ethernet && 
      hs->hostbatch[0]->af() == AF_INET &&
      hs->hostbatch[0]->directlyConnected() && 
      o.sendpref != PACKET_SEND_IP_STRONG) {
    arpping(hs->hostbatch, hs->current_batch_sz);///局域网内主机发现的执行函数
    arpping_done = true;
  }
 
  /* No other interface types are supported by ND ping except devt_ethernet
     at the moment. */
  if (hs->hostbatch[0]->ifType() == devt_ethernet &&
      hs->hostbatch[0]->af() == AF_INET6 &&
      hs->hostbatch[0]->directlyConnected() &&
      o.sendpref != PACKET_SEND_IP_STRONG) {
    arpping(hs->hostbatch, hs->current_batch_sz);
    arpping_done = true;
  }
  ///若命令行指定了--send-eth，并判断到当前接口类型为ethernet网卡，
  ///对每一个状态不是HOST_DOWN且未超时的主机，设置下一跳MAC地址
  gettimeofday(&now, NULL);
  if ((o.sendpref & PACKET_SEND_ETH) && 
      hs->hostbatch[0]->ifType() == devt_ethernet) {
    for (i=0; i < hs->current_batch_sz; i++) {
      if (!(hs->hostbatch[i]->flags & HOST_DOWN) && 
          !hs->hostbatch[i]->timedOut(&now)) {
        if (!setTargetNextHopMAC(hs->hostbatch[i])) {
          fatal("%s: Failed to determine dst MAC address for target %s", 
              __func__, hs->hostbatch[i]->NameIP());
        }
      }
    }
  }
```

**列表扫描&无PING扫描**

直接将目标主机状态设置成HOST_UP，当用户指定列表扫描或用户指定不需进行主机发现，此处将目标主机标示为在线的。

```c
/* TODO: Maybe I should allow real ping scan of directly connected
     ethernet hosts? */
  /* Then we do the mass ping (if required - IP-level pings) */
  ///探测方式2：若指定不进行PING操作（如命令行指定了-Pn或-sL都不会进行PING操作）而arpping_done为被标记
  ///或指定扫描自己回环网口，那么都在此处将主机标记位HOST_UP.
  if ((pingtype == PINGTYPE_NONE && !arpping_done) || hs->hostbatch[0]->ifType() == devt_loopback) {
    for (i=0; i < hs->current_batch_sz; i++) {
      if (!hs->hostbatch[i]->timedOut(&now)) {
        initialize_timeout_info(&hs->hostbatch[i]->to);
        hs->hostbatch[i]->flags |= HOST_UP; /*hostbatch[i].up = 1;*/
        if (pingtype == PINGTYPE_NONE && !arpping_done)///用户指定该主机为HOST_UP，例如用户已知某个目标已经开启，
          hs->hostbatch[i]->reason.reason_id = ER_USER;///就可以通过-Pn选项让Nmap不进行PING过程。
        else
          hs->hostbatch[i]->reason.reason_id = ER_LOCALHOST;///本地主机，当然为HOST_UP
      }
    }
  } 
```

**其他扫描方式**

默认情况下，nmap会发送四种数据包探测目标主机是否在线：

* ICMP echo request

* aTCP SYN packet to port 443

* aTCP ACK packet to port 80

* an ICMP timestamp request

只要收到任何探测包回复，就证明目标主机在线。

```c
else if (!arpping_done) {///探测方式3：其他情况，则采用massping方式探测主机是否在线
    massping(hs->hostbatch, hs->current_batch_sz, ports);
  }
  ///若命令行没有指定-n选项（含义是不做DNS/RDNS解析），那么这里对rdns进行解析
  if (!o.noresolve)
    nmap_mass_rdns(hs->hostbatch, hs->current_batch_sz);
  ///返回hostbatch中当前next_batch_no所在的主机（next_host()会批量解析主机IP，下一次进入时直接返回已解析的地址）。
  return hs->hostbatch[hs->next_batch_no++];
```
