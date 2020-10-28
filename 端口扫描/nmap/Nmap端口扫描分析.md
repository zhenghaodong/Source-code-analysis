# Nmap端口扫描分析

## 结构

nmap的主要端口扫描功能在scan_engine.cc和scan_engine.h文件中实现。在实际运行的过程中，端口扫描功能还依赖于nmap-services数据库文件(该文件描述了常见注册端口对应的服务名称以及该端口开放的频率，根据此概率可以方便指定扫描覆盖的范围)。

### UltraScanInfo

该类记录了端口扫描过程的信息。

```c
class UltraScanInfo {
public:
  UltraScanInfo();
  UltraScanInfo(vector<Target *> &Targets, struct scan_lists *pts, stype scantype) { Init(Targets, pts, scantype); }
  ~UltraScanInfo();
  /* Must call Init if you create object with default constructor */
  void Init(vector<Target *> &Targets, struct scan_lists *pts, stype scantp);

  unsigned int numProbesPerHost();

  /* Consults with the group stats, and the hstats for every
     incomplete hosts to determine whether any probes may be sent.
     Returns true if they can be sent immediately.  If when is non-NULL,
     it is filled with the next possible time that probes can be sent
     (which will be now, if the function returns true */
  bool sendOK(struct timeval *tv);
  //执行的扫描类型信息
  stype scantype;
  bool tcp_scan; /* scantype is a type of TCP scan */
  bool udp_scan;
  bool sctp_scan; /* scantype is a type of SCTP scan */
  bool prot_scan;
  bool ping_scan; /* Includes trad. ping scan & arp scan */
  bool ping_scan_arp; /* ONLY includes arp ping scan */
  bool ping_scan_nd; /* ONLY includes ND ping scan */
  bool noresp_open_scan; /* Whether no response means a port is open */

  /* massping state. */
  /* If ping_scan is true (unless ping_scan_arp is also true), this is the set
     of ping techniques to use (ICMP, raw ICMP, TCP connect, raw TCP, or raw
     UDP). */
  struct pingtech ptech;

  bool isRawScan();

  struct timeval now; /* Updated after potentially meaningful delays.  This can
       be used to save a call to gettimeofday() */
  GroupScanStats *gstats;
  struct ultra_scan_performance_vars perf;
  /* A circular buffer of the incompleteHosts.  nextIncompleteHost() gives
     the next one.  The first time it is called, it will give the
     first host in the list.  If incompleteHosts is empty, returns
     NULL. */
  HostScanStats *nextIncompleteHost();
  /* Removes any hosts that have completed their scans from the incompleteHosts
     list, and remove any hosts from completedHosts which have exceeded their
     lifetime.  Returns the number of hosts remov
```

### GroupScanStats

用于管理端口扫描过程中一组主机的整体统计状态。

```c
/* These are ultra_scan() statistics for the whole group of Targets */
class GroupScanStats {
public:
  struct timeval timeout; /* The time at which we abort the scan */
  /* Most recent host tested for sendability */
  struct sockaddr_storage latestip; 
  GroupScanStats(UltraScanInfo *UltraSI);
  ~GroupScanStats();
  void probeSent(unsigned int nbytes);
  /* Returns true if the GLOBAL system says that sending is OK. */
  bool sendOK(struct timeval *when); 
  /* Total # of probes outstanding (active) for all Hosts */
  int num_probes_active; 
  UltraScanInfo *USI; /* The USI which contains this GSS.  Use for at least
       getting the current time w/o gettimeofday() */
  struct ultra_timing_vals timing;
  struct timeout_info to; /* Group-wide packet rtt/timeout info */
  int numtargets; /* Total # of targets scanned -- includes finished and incomplete hosts */
  int numprobes; /* Number of probes/ports scanned on each host */
  /* The last time waitForResponses finished (initialized to GSS creation time */
  int probes_sent; /* Number of probes sent in total.  This DOES include pings and retransmissions */

  /* The most recently received probe response time -- initialized to scan
     start time. */
  struct timeval lastrcvd;
  /* The time the most recent ping was sent (initialized to scan begin time) */
  struct timeval lastping_sent;
  /* Value of numprobes_sent at lastping_sent time -- to ensure that we don't
     send too many pings when probes are going slowly. */
  int lastping_sent_numprobes; 

  /* These two variables control minimum- and maximum-rate sending (--min-rate
     and --max-rate). send_no_earlier_than is for --max-rate and
     send_no_later_than is for --min-rate; they have effect only when the
     respective command-line option is given. An attempt is made to keep the
     sending rate within the interval, however for send_no_later_than it is not
     guaranteed. */
  struct timeval send_no_earlier_than;
  struct timeval send_no_later_than;

  /* The host to which global pings are sent. T
```

### HostScanStats

管理单个目标主机的扫描统计状态。上述两个结构中存放的都是HostScanStats指针类型数据。

```c
/* The ultra_scan() statistics that apply to individual target hosts in a 
   group */
class HostScanStats {
public:
  Target *target; /* A copy of the Target that these stats refer to. */
  HostScanStats(Target *t, UltraScanInfo *UltraSI);
  ~HostScanStats();
  int freshPortsLeft(); /* Returns the number of ports remaining to probe */
  int next_portidx; /* Index of the next port to probe in the relevent
           ports array in USI.ports */
  bool sent_arp; /* Has an ARP probe been sent for the target yet? */

  /* massping state. */
  /* The index of the next ACK port in o.ping_ackprobes to probe during ping
     scan. */
  int next_ackportpingidx;
  /* The index of the next SYN port in o.ping_synprobes to probe during ping
     scan. */
  int next_synportpingidx;
  /* The index of the next UDP port in o.ping_udpprobes to probe during ping
     scan. */
  int next_udpportpingidx;
  /* The index of the next SCTP port in o.ping_protoprobes to probe during ping
     scan. */
  int next_sctpportpingidx;
  /* The index of the next IP protocol in o.ping_protoprobes to probe during ping
     scan. */
  int next_protoportpingidx;
  /* Whether we have sent an ICMP echo request. */
  bool sent_icmp_ping;
  /* Whether we have sent an ICMP address mask request. */
  bool sent_icmp_mask;
  /* Whether we have sent an ICMP timestamp request. */
  bool sent_icmp_ts;

  /* Have we warned that we've given up on a port for this host yet? Only one
     port per host is reported. */
  bool retry_capped_warned;

  void probeSent(unsigned int nbytes);

  /* How long I am currently willing to wait for a probe response
     before considering it timed out.  Uses the host values from
     target if they are available, otherwise from gstats.  Results
     returned in MICROseconds.  */
  unsigned long probeTimeout();

  /* How long I'll wait until completely giving up on a probe.
     Timedout probes are often marked as such (and sometimes
     considered a drop), but kept in the list juts in case they come
     really late.  But after
```

### UltraProbe

用于管理每一个探测包的信息。

```c
class UltraProbe {
public:
  UltraProbe();
  ~UltraProbe();
  enum UPType { UP_UNSET, UP_IP, UP_CONNECT, UP_RPC, UP_ARP, UP_ND } type; /* The type of probe this is */

  /* Sets this UltraProbe as type UP_IP and creates & initializes the
     internal IPProbe.  The relevent probespec is necessary for setIP
     because pspec.type is ambiguous with just the ippacket (e.g. a
     tcp packet could be PS_PROTO or PS_TCP). */
  void setIP(u8 *ippacket, u32 iplen, const probespec *pspec);
  /* Sets this UltraProbe as type UP_CONNECT, preparing to connect to given
   port number*/
  void setConnect(u16 portno);
  /* Pass an arp packet, including ethernet header. Must be 42bytes */
  void setARP(u8 *arppkt, u32 arplen);
  void setND(u8 *ndpkt, u32 ndlen);
  // The 4 accessors below all return in HOST BYTE ORDER
  // source port used if TCP, UDP or SCTP
  u16 sport() const {
    switch (mypspec.proto) {
      case IPPROTO_TCP:
  return probes.IP.pd.tcp.sport;
      case IPPROTO_UDP:
  return probes.IP.pd.udp.sport;
      case IPPROTO_SCTP:
  return probes.IP.pd.sctp.sport;
      default:
  return 0;
    }
    /* not reached */
  }
  // destination port used if TCP, UDP or SCTP
  u16 dport() const {
    switch (mypspec.proto) {
      case IPPROTO_TCP:
  return mypspec.pd.tcp.dport;
      case IPPROTO_UDP:
  return mypspec.pd.udp.dport;
      case IPPROTO_SCTP:
  return mypspec.pd.sctp.dport;
      default:
  /* dport() can get called for other protos if we
   * get ICMP responses during IP proto scans. */
  return 0;
    }
    /* not reached */
  }
  u16 ipid() const { return probes.IP.ipid; }
  u32 tcpseq() const; // TCP sequence number if protocol is TCP
  u32 sctpvtag() const; // SCTP vtag if protocol is SCTP
  /* Number, such as IPPROTO_TCP, IPPROTO_UDP, etc. */
  u8 protocol() const { return mypspec.proto; }
  ConnectProbe *CP() { return probes.CP; } // if type == UP_CONNECT
  // Arpprobe removed because not used.
  //  ArpProbe *AP() { return probes.AP; } // if UP_ARP
  // Returns the protocol number, such as IPPROTO
```

## 逻辑

### 端口扫描流程

1. 加载UDP负载到映射表；
2. 创建UltraScanInfo对象记录端口扫描过程信息；
3. 开始嗅探(bigin_sniffer())；
4. 如果主机列表没有扫描完毕，则向目标主机发送PING；
5. 对未完成的包进行重传并对retry_stack的探测包重传；
6. 添加新类型的探测包；
7. 打印扫描状态并等待接收返回包；
8. 根据接收包做处理；
9. 重复4-8直到主机列表扫描完毕；
10. 停止发送频率度量并保存计算的超时值；
11. 打印扫描详细信息与调试信息；
12. 删除UltraScanInfo对象。

```c
/* 3rd generation Nmap scanning function. Handles most Nmap port scan types.
The parameter to gives group timing information, and if it is not NULL,
changed timing information will be stored in it when the function returns. It
exists so timing can be shared across invocations of this function. If to is
NULL (its default value), a default timeout_info will be used. */
void ultra_scan(vector<Target *> &Targets, struct scan_lists *ports, 
stype scantype, struct timeout_info *to) {
UltraScanInfo *USI = NULL;///扫描信息控制类
o.current_scantype = scantype;///标记当前扫描类型，用于输出
init_payloads(); /* Load up _all_ payloads into a mapped table */
if (Targets.size() == 0) {
return;
}
#ifdef WIN32
if (scantype != CONNECT_SCAN && Targets[0]->ifType() == devt_loopback) {
log_write(LOG_STDOUT, "Skipping %s against %s because Windows does not support scanning your own machine (localhost) this way.\n", scantype2str(scantype), Targets[0]->NameIP());
return;
}
#endif
// Set the variable for status printing
o.numhosts_scanning = Targets.size();
startTimeOutClocks(Targets);
USI = new UltraScanInfo(Targets, ports, scantype);
/* Use the requested timeouts. */
if (to != NULL)
USI->gstats->to = *to;
if (o.verbose) {
char targetstr[128];
bool plural = (Targets.size() != 1);
if (!plural) {
(*(Targets.begin()))->NameIP(targetstr, sizeof(targetstr));
} else Snprintf(targetstr, sizeof(targetstr), "%d hosts", (int) Targets.size());
log_write(LOG_STDOUT, "Scanning %s [%d port%s%s]\n", targetstr, USI->gstats->numprobes, (USI->gstats->numprobes != 1)? "s" : "", plural? "/host" : "");
}
///begin_sniffer()开启libpcap并设置pcap filter，以便接收目标主机返回的数据包
begin_sniffer(USI, Targets);
while(!USI->incompleteHostsEmpty()) { 
///向目标机发送探测包（probe）
doAnyPings(USI); 
///重传未完成探测过程的数据包
doAnyOutstandingRetransmits(USI); // Retransmits from probes_outstanding
/* Retransmits from retry_stack -- goes after OutstandingRetransmits for
memory consumption reasons */
///
doAnyRetryStackRetransmits(USI);
///检查需要进行的新的探测包类型。
doAnyNewProbes(USI);
gettimeofday(&USI->now, NULL);
// printf("TRACE
```