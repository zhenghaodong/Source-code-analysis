# Nmap框架分析

## 功能结构概览

<details>
  <summary>Nmap主要功能</summary>
	
  * 主机发现
	
  * 服务器版本探测
  
  * 操作系统探测
  
  * 网络追踪
  
  * Nmap脚本引擎
  
</details>

<details>
  <summary>Nmap文件类型</summary>
	
  * 源码(.cc，.lua文件等)
	
  * 数据库文件(nmap-os-db，nmap-service-probes等)
  
  * 编译时的基本文件(Makefile，config等)
  
  * 注释、提示文件(README-WIN32等)
  
</details>


<details>
  <summary>Nmap目录结构</summary>
	
```	
	
   Nmap/
    ├─docs（Nmap相关文档，包括License、usage说明及XMLschema文件等）
    │  ├─licenses   
    │  └─man-xlate
    ├─libdnet-stripped（libdnet：简单的网络接口开源库）
    │  ├─config
    │  ├─include
    │  └─src
    ├─liblinear（LIBLINEAR：负责大型线性分类的开源库）
    │  └─blas
    ├─liblua（Lua脚本语言源码库）
    ├─libnetutil（Nmap实现的基本的网络实用函数）
    ├─libpcap（开源的抓包代码库libpcap）
    │  ├─bpf
    │  ├─ChmodBPF
    │  ├─lbl
    │  ├─missing
    │  ├─msdos
    │  ├─NMAP_MODIFICATIONS
    │  ├─packaging
    │  ├─pcap
    │  ├─SUNOS4
    │  ├─tests
    │  └─Win32
    ├─libpcre（Perl兼容的正则表达式开源库libpcre）
    ├─macosx（该目录负责支持苹果的操作系统MACOS X）
    │  └─nmap.pmdoc
    ├─mswin32（该目录负责支持Windows操作系统）
    │  ├─lib
    │  ├─license-format
    │  ├─NET
    │  ├─NETINET
    │  ├─nsis
    │  ├─OpenSSL
    │  ├─pcap-include
    │  ├─RPC
    │  └─winpcap
    ├─nbase（Nmap封装的基础使用程序库，包括string/path/random等）
    ├─ncat（Ncat是Nmap项目组实现的新版的netcat：强大的网络工具）
    │  ├─certs
    │  ├─docs
    │  └─test
    ├─ndiff（Ndiff是用于比较Nmap扫描结果的实用命令）
    │  ├─docs
    │  └─test-scans
    ├─nmap-update（负责Nmap更新相关操作）
    ├─nping（Nping是Nmap项目组实现的新版的Hping：网络探测与构建packet）
    │  └─docs
    ├─nselib（Nmap使用Lua语言编写的常用的脚本库）
    │  └─data
    ├─nsock（Nmap实现的并行的SocketEvent处理库）
    │  ├─include
    │  └─src
    ├─scripts（Nmap提供常用的扫描检查的lua脚本）
    ├─todo（介绍Nmap项目将来开发的具体任务）
    └─zenmap（Nmap的官方的图形界面程序，由python语言编写）
       ├─install_scripts
       ├─radialnet
       ├─share
       ├─test
       ├─zenmapCore
       └─zenmapGUI
       
```

</details>

## 执行流程

### 入口

nmap入口文件为main.cc，main.cc中main函数有以下功能：

- 检查环境变量NMAP_ARGS
- 检查有没有–resume参数
- 判断是resume之前扫描，还是新请求
- 调用nmap_main()函数

因此nmap_main()函数才是实际的主函数。

### nmap_main

函数在开始时定义了一些相关变量和对象：

```c
int nmap_main(int argc, char *argv[]) {
  int i;
  vector<Target *> Targets;
  time_t now;
  struct hostent *target = NULL;
  time_t timep;
  char mytime[128];
  addrset exclude_group;
  #ifndef NOLUA
  /* Only NSE scripts can add targets */
  NewTargets *new_targets = NULL;
  /* Pre-Scan and Post-Scan script results datastructure */
  ScriptResults *script_scan_results = NULL;
  #endif
  char **host_exp_group;
  int num_host_exp_groups;
  HostGroupState *hstate = NULL;
  unsigned int ideal_scan_group_sz = 0;
  Target *currenths;
  char *host_spec = NULL;
  char myname[MAXHOSTNAMELEN + 1];
  int sourceaddrwarning = 0; /* Have we warned them yet about unguessable
                                source addresses? */
  unsigned int targetno;
  char hostname[MAXHOSTNAMELEN + 1] = "";
  struct sockaddr_storage ss;
  size_t sslen;
  char **fakeargv = NULL;x
	...
```

其中Target是主机变量，其中包括了主机的地址等信息。接着会对端口以及地址信息进行初始化：

```
/* Before we randomize the ports scanned, we must initialize PortList class. */
  if (o.ipprotscan)
    PortList::initializePortMap(IPPROTO_IP,  ports.prots, ports.prot_count);
  if (o.TCPScan())
    PortList::initializePortMap(IPPROTO_TCP, ports.tcp_ports, ports.tcp_count);
  if (o.UDPScan())
    PortList::initializePortMap(IPPROTO_UDP, ports.udp_ports, ports.udp_count);
  if (o.SCTPScan())
    PortList::initializePortMap(IPPROTO_SCTP, ports.sctp_ports, ports.sctp_count);

  if (o.randomize_ports) {
    if (ports.tcp_count) {
      shortfry(ports.tcp_ports, ports.tcp_count);
      // move a few more common ports closer to the beginning to speed scan
      random_port_cheat(ports.tcp_ports, ports.tcp_count);
    }
    if (ports.udp_count)
      shortfry(ports.udp_ports, ports.udp_count);
    if (ports.sctp_count)
      shortfry(ports.sctp_ports, ports.sctp_count);
    if (ports.prot_count)
      shortfry(ports.prots, ports.prot_count);
  }

  addrset_init(&exclude_group);

  /* lets load our exclude list */
  if (o.excludefd != NULL) {
    load_exclude_file(&exclude_group, o.excludefd);
    fclose(o.excludefd);
  }
  if (o.exclude_spec != NULL) {
    load_exclude_string(&exclude_group, o.exclude_spec);
  }

  if (o.debugging > 3)
    dumpExclude(&exclude_group);
```

在端口初始化的过程中，首先将端口顺序打乱，然后将常见的端口移到前面以便最快发现有效端口。对于地址初始化，主要是加载排除地址的信息。

接着创建主机组状态然后进入主循环：

```c
/* Time to create a hostgroup state object filled with all the requested
     machines. The list is initially empty. It is refilled inside the loop
     whenever it is empty. */
  ///分配字符串数组，用以保存各个主机表达式字符串的地址
  host_exp_group = (char **) safe_malloc(o.ping_group_sz * sizeof(char *));
  num_host_exp_groups = 0;
 
  hstate = new HostGroupState(o.ping_group_sz, o.randomize_hosts,
                  host_exp_group, num_host_exp_groups);
 
  do {
    ///确定最佳的host group的大小，该大小取决于扫描方式与网络速度。
    ideal_scan_group_sz = determineScanGroupSize(o.numhosts_scanned, &ports);
	///对host group进行主机发现
    ///以下的while()将依次进行主机发现，确定主机是否在线。
    ///若该主机在线加入该host group，用于后续的操作。当数量达到最佳大小时，退出循环。
    while(Targets.size() < ideal_scan_group_sz) {
      o.current_scantype = HOST_DISCOVERY;  ///设置扫描状态:HOST_DICOVERY
      currenths = nexthost(hstate, &exclude_group, &ports, o.pingtype); ///主机发现的核心函数
      ///如果当前主机发现无法找到有效主机，那么会做以下尝试：
      ///1）更换主机表达式（host expressions）
      ///例如：nmap 192.168.1.1/24 10.10.30.55-100，192.168.1.x不能再发现主机时候，切换为10.30.55-100
      ///2）将执行脚本扫描时发现的主机，加入主机表达式组host_exp_group
      ///3) 建立新的主机组状态，并做最后的主机发现尝试
      if (!currenths) {
        /* Try to refill with any remaining expressions */
        /* First free the old ones */
        for(i=0; i < num_host_exp_groups; i++)
          free(host_exp_group[i]);
        num_host_exp_groups = 0;
        /* Now grab any new expressions */
        while(num_host_exp_groups < o.ping_group_sz && 
          (!o.max_ips_to_scan || o.max_ips_to_scan > o.numhosts_scanned + (int) Targets.size() + num_host_exp_groups) &&
          (host_spec = grab_next_host_spec(o.inputfd, o.generate_random_ips, argc, fakeargv))) {
            // For purposes of random scan
            host_exp_group[num_host_exp_groups++] = strdup(host_spec);
        }
#ifndef NOLUA
        /* Add the new NSE discovered targets to the scan queue */
        if (o.script) {
          if (new_targets != NULL) {
            while (new_targets->get_queued() > 0 && num_host_exp_groups < o.ping_group_sz) {
              std::string target_spec = new_targets->read();
              if (target_spec.length())
                host_exp_group[num_host_exp_groups++] = strdup(target_spec.c_str());
            }
 
            if (o.debugging > 3)
              log_write(LOG_PLAIN,
                  "New targets in the scanned cache: %ld, pending ones: %ld.\n",
                  new_targets->get_scanned(), new_targets->get_queued());
          }
        }
#endif
        if (num_host_exp_groups == 0)  ///当没有其他的主机表达式时，退出整个主机发现循环
          break;
        delete hstate;
        hstate = new HostGroupState(o.ping_group_sz, o.randomize_hosts,host_exp_group,
                        num_host_exp_groups);
      
        /* Try one last time -- with new expressions */
        currenths = nexthost(hstate, &exclude_group, &ports, o.pingtype);
        if (!currenths)
          break;
      }
    
      if (currenths->flags & HOST_UP && !o.listscan) 
        o.numhosts_up++;
    
      if ((o.noportscan && !o.traceroute
#ifndef NOLUA
      && !o.script
#endif
          ) || o.listscan) {
        ///当不进行端口扫描（-sn）并且没有指定traceroute和脚本的话，那么扫描就到此处就结束。
        ///或当进行列表扫描（-sL，只列举出主机IP，并不真正扫描）时，扫描也到此结束。		
        /* We're done with the hosts */
        if (currenths->flags & HOST_UP || o.verbose) {
          xml_start_tag("host");
          write_host_header(currenths);
          printmacinfo(currenths);
          //  if (currenths->flags & HOST_UP)
          //  log_write(LOG_PLAIN,"\n");
          printtimes(currenths);
          xml_end_tag();
          xml_newline();
          log_flush_all();
        }
        delete currenths;
        o.numhosts_scanned++;
        continue;
      }
      ///若配置要伪造源IP地址（-S ip），将命令行中传入的地址写入当前主机源地址
      if (o.spoofsource) {
        o.SourceSockAddr(&ss, &sslen);
        currenths->setSourceSockAddr(&ss, sslen);
      }
      
      ///如果主机状态为HOST_DOWN，那么需要根据配置考虑是否输出其状态
      ///输出条件：verbose级别大于0，并且没有指定openonly或已确定有开放端口。
      /* I used to check that !currenths->weird_responses, but in some
         rare cases, such IPs CAN be port successfully scanned and even
         connected to */
      if (!(currenths->flags & HOST_UP)) {
        if (o.verbose && (!o.openOnly() || currenths->ports.hasOpenPorts())) {
          xml_start_tag("host");
          write_host_header(currenths);
          xml_end_tag();
          xml_newline();
        }
        delete currenths;
        o.numhosts_scanned++;
        continue;
      }
      ///如果是RawScan(即涉及到构建原始的packet的扫描方式，如SYN/FIN/ARP等等),
      ///需要设置套接字源IP地址
      if (o.RawScan()) {
        if (currenths->SourceSockAddr(NULL, NULL) != 0) {
          if (o.SourceSockAddr(&ss, &sslen) == 0) {
		    ///若全局变量o中已有源IP地址，直接赋值给当前目标机
            currenths->setSourceSockAddr(&ss, sslen);
          } else {
		    ///否则，需要重新查询、解析主机来获取源地址
            if (gethostname(myname, MAXHOSTNAMELEN) ||
                resolve(myname, 0, 0, &ss, &sslen, o.af()) == 0)
              fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n"); 
        
            o.setSourceSockAddr(&ss, sslen);
            currenths->setSourceSockAddr(&ss, sslen);
            if (! sourceaddrwarning) {
              error("WARNING:  We could not determine for sure which interface to use, so we are guessing %s .  If this is wrong, use -S <my_IP_address>.",
                  inet_socktop(&ss));
                sourceaddrwarning = 1;
            }
          }
        }
 
        if (!currenths->deviceName())///网卡名字，在主机发现函数nexthost()中设置
          fatal("Do not have appropriate device name for target");
        
        ///如果新发现的主机与该主机组类型不大相同，那么考虑将此主机放入新的主机组内。
        ///因为对主机分组是为了加快扫描速度，所以尽可能特征相似的主机组合在一起。
        ///流水线工作模式的扫描思想。
        /* Hosts in a group need to be somewhat homogeneous. Put this host in
           the next group if necessary. See target_needs_new_hostgroup for the
           details of when we need to split. */
        if (target_needs_new_hostgroup(Targets, currenths)) {
          returnhost(hstate);
          o.numhosts_up--;
          break;
        }
        ///设置IP诱骗时，将当前主机真实IP放入decoyturn位置。
        ///其他的诱骗IP地址在parse options时已经确定。
        o.decoys[o.decoyturn] = currenths->v4source();    
      }
      ///将新发现的主机加入Targets向量
      Targets.push_back(currenths);        
    }///一次分组的主机发现在此处结束，接下来执行端口扫描、服务侦测、OS侦测、脚本扫描等。
```

在主机发现之后，进入端口扫描部分：

```c
if (!o.noportscan) {
      ///<Start---------端口扫描----------Start>
      ///针对用户指定的不同扫描方式，分别使用不同参数调用ultra_scan()
      ///ultra_scan()设计精巧，用统一的接口处理大多数的端口扫描
      // Ultra_scan sets o.scantype for us so we don't have to worry
      if (o.synscan)
        ultra_scan(Targets, &ports, SYN_SCAN);
      
      if (o.ackscan)
        ultra_scan(Targets, &ports, ACK_SCAN);
      
      if (o.windowscan)
        ultra_scan(Targets, &ports, WINDOW_SCAN);
      
      if (o.finscan)
        ultra_scan(Targets, &ports, FIN_SCAN);
      
      if (o.xmasscan)
        ultra_scan(Targets, &ports, XMAS_SCAN);
      
      if (o.nullscan)
        ultra_scan(Targets, &ports, NULL_SCAN);
      
      if (o.maimonscan)
        ultra_scan(Targets, &ports, MAIMON_SCAN);
      
      if (o.udpscan)
        ultra_scan(Targets, &ports, UDP_SCAN);
      
      if (o.connectscan)
        ultra_scan(Targets, &ports, CONNECT_SCAN);
      
      if (o.sctpinitscan)
        ultra_scan(Targets, &ports, SCTP_INIT_SCAN);
      
      if (o.sctpcookieechoscan)
        ultra_scan(Targets, &ports, SCTP_COOKIE_ECHO_SCAN);
      
      if (o.ipprotscan)
        ultra_scan(Targets, &ports, IPPROT_SCAN);
      
      /* These lame functions can only handle one target at a time */
      if (o.idlescan) {
        for(targetno = 0; targetno < Targets.size(); targetno++) {
           o.current_scantype = IDLE_SCAN;
           keyWasPressed(); // Check if a status message should be printed
           idle_scan(Targets[targetno], ports.tcp_ports,
                                  ports.tcp_count, o.idleProxy, &ports);
        }
      }
      if (o.bouncescan) {
        for(targetno = 0; targetno < Targets.size(); targetno++) {
           o.current_scantype = BOUNCE_SCAN;
           keyWasPressed(); // Check if a status message should be printed
          if (ftp.sd <= 0) ftp_anon_connect(&ftp);
          if (ftp.sd > 0) bounce_scan(Targets[targetno], ports.tcp_ports,
                                      ports.tcp_count, &ftp);
        }
      }
      
```

端口扫描主要有以下几种方式：

* TCP SYN扫描：默认扫描方式，发送SYN到目标端口，收到SYN/ACK回复代表端口开放；收到RST包代表端口关闭；未收到包代表端口被屏蔽
* TCP连接扫描：与目标建立TCP连接
* TCP ACK扫描：向目标主机端口发送ACK包，若收到RST包则证明端口没有被防火墙屏蔽；没收到则证明被屏蔽
* TCP FIN/Xmas/NULL scanning
* UDP扫描：发送udp包，如果收到ICMP port unreachable，则代表端口关闭，如果没有收到则证明udp端口是开放或者屏蔽的

服务于版本扫描：

```c
if (o.servicescan) {
    o.current_scantype = SERVICE_SCAN; 
 
    service_scan(Targets);
}
 
if (o.servicescan) {
    /* This scantype must be after any TCP or UDP scans since it
    * get's it's port scan list from the open port list of the current
    * host rather than port list the user specified.
    */
    for(targetno = 0; targetno < Targets.size(); targetno++)
        pos_scan(Targets[targetno], NULL, 0, RPC_SCAN);
}
```

脚本扫描：

```c
if (o.osscan){
    OSScan os_engine;
    os_engine.os_scan(Targets);
}
///若需要路径追踪，在此处调用traceroute获取路径
if (o.traceroute)
    traceroute(Targets);
///脚本扫描
#ifndef NOLUA
if(o.script || o.scriptversion) {
    script_scan(Targets, SCRIPT_SCAN);
}
#endif
```

