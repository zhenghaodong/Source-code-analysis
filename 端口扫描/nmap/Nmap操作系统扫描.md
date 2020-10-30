# Nmap操作系统扫描

## 原理

Nmap使用TCP/IP协议栈指纹来识别不同的操作系统和设备。RFC规范中有些地方对TCP/IP的实现并没有强制规定，因此不同的TCP/IP方案中可能有特殊的处理方式，Nmap根据这些细节来判断操作系统类型。

* Nmap内包含很多系统已知指纹(nmap-os-db中)，将此指纹数据库作为指纹对比的样本库
* 分别挑选open合closed的端口，向其发送设计过的TCP/UDP/ICMP数据包。根据返回包生成一份系统指纹
* 将探测得到的指纹与数据库中的指纹进行对比，查找匹配的系统

## 框架

### OSScan

该类将IPV4和IPV6的操作系统扫描过程封装起来，提供统一的接口os_scan()。

* 提供扫描接口os_scan()
* 提供重置函数接口(初始化必要的变量)
* 保存ip的协议版本
* 执行分块与扫描过程，确定并发执行的数量
* 针对IPV4进行操作系统扫描
* 针对IPV6进行操作系统扫描

```c
/** This is the class that performs OS detection (both IPv4 and IPv6).
  * Using it is simple, just call os_scan() passing a list of targets.
  * The results of the detection will be stored inside the supplied
  * target objects. */
class OSScan {
 
 private:
  int ip_ver;             /* IP version for the OS Scan (4 or 6) */
  int chunk_and_do_scan(std::vector<Target *> &Targets, int family);
  int os_scan_ipv4(std::vector<Target *> &Targets);
  int os_scan_ipv6(std::vector<Target *> &Targets);
        
  public:
   OSScan();
   ~OSScan();
   void reset();
   int os_scan(std::vector<Target *> &Targets);
};
```

### OSScanInfo

管理全部主机的扫描过程，维护操作系统扫描未完成的列表。

* 未完成扫描列表
* 起始扫描时间
* 未完成列表访问接口读取总数，获取下一个，查找主机，重置迭代器
* 移除已完成主机

### HostOsScanInfo

管理单个主机的操作系统扫描信息

* 对应的目标机Target *target
* 被包含的OsScanInfo对象地址
* 当前主机产生的指纹信息FingerPrint *FPs
* 记录是否超时、是否完成
* 单个OS扫描每一轮的统计信息HostOsScanStats *hss
* 指纹扫描结果与匹配情况

```c
/* The overall os scan information of a host:
 *  - Fingerprints gotten from every scan round;
 *  - Maching results of these fingerprints.
 *  - Is it timeout/completed?
 *  - ... */
class HostOsScanInfo {
 
 public:
  HostOsScanInfo(Target *t, OsScanInfo *OSI);
  ~HostOsScanInfo();
 
  Target *target;       /* The target                                  */
  FingerPrintResultsIPv4 *FPR;
  OsScanInfo *OSI;      /* The OSI which contains this HostOsScanInfo  */
  FingerPrint **FPs;    /* Fingerprints of the host                    */
  FingerPrintResultsIPv4 *FP_matches; /* Fingerprint-matching results      */
  bool timedOut;        /* Did it time out?                            */
  bool isCompleted;     /* Has the OS detection been completed?        */
  HostOsScanStats *hss; /* Scan status of the host in one scan round   */
};
```

### HostOsScanStats

管理每个主机每一轮OS扫描的统计信息。

* 扫描探测包的管理
* 以太网信息管理
* 指纹信息的管理
* TCP序号、IPID、启动时间等信息管理
* 其他杂项信息

### OFProbe

管理OS扫描过程中需要的探测包信息，该对象中本身只包含用于构建探测包的关键属性而不包含探测包本身。

## 流程

* 根据地址划分不同的扫描组
* 做IPV4的操作系统探测
* 做IPV6的操作系统探测
* 返回两类扫描结果

**IPV4操作系统探测原理**：

> IPV6探测原理相同，但是不同点在于发送探测包、分析回复包、匹配过程与IPV4有差异。IPV6操作系统探测主要调用FPengine部分来实现。

1. 初始化扫描性能变量
2. 打开libpcap设置filter进行包嗅探
3. 如果OS扫描没有完成，则准备此轮OS探测环境
4. 做顺序产生测试sequence_tests
5. 做TCP/UDP/ICMP测试
6. 处理此轮扫描结果
7. 移除过期未匹配主机

* 重复检查OS是否扫描完毕，如果扫描完毕，则将未匹配主机放入未完成列表
* 对未完成列表的主机进行最接近指纹匹配
* 返回IPV4操作系统扫描结果

```c
/* This function performs the OS detection. It processes the supplied list of
 * targets and classifies it into two groups: IPv4 and IPv6 targets. Then,
 * OS detection is carried out for those two separate groups. It returns
 * OP_SUCCESS on success or OP_FAILURE in case of error. */
int OSScan::os_scan(vector<Target *> &Targets) {
  vector<Target *> ip4_targets; ///IPv4类型地址的目标机
  vector<Target *> ip6_targets; ///IPv6类型地址的目标机
  int res4 = OP_SUCCESS, res6 = OP_SUCCESS;
 
  /* Make sure we have at least one target */
  if (Targets.size() <= 0)
    return OP_FAILURE;
 
  /* Classify targets into two groups: IPv4 and IPv6 */
  ///先根据地址将目标机划分到不同向量里，因为两类目标机扫描过程不同
  for (size_t i = 0; i < Targets.size(); i++) {
      if (Targets[i]->af() == AF_INET6)
          ip6_targets.push_back(Targets[i]);
      else
          ip4_targets.push_back(Targets[i]);
  }
 
  /* Do IPv4 OS Detection */
  ///在os_scan_ipv4()函数中具体实现IPv4的操作系统探测的过程
  if (ip4_targets.size() > 0)
      res4 = this->os_scan_ipv4(ip4_targets);
 
  /* Do IPv6 OS Detection */
  ///在os_scan_ipv6()函数中具体实现IPv6的操作系统探测的过程
  if (ip6_targets.size() > 0)
      res6 = this->os_scan_ipv6(ip6_targets);
 
  /* If both scans were succesful, return OK */
  if (res4 == OP_SUCCESS && res6 == OP_SUCCESS)
    return OP_SUCCESS;
  else
    return OP_FAILURE;
}
 
 
/* Performs the OS detection for IPv4 hosts. This method should not be called
 * directly. os_scan() should be used instead, as it handles chunking so
 * you don't do too many targets in parallel */
 ///IPv4的操作系统探测的实现函数，由os_scan()来调用。
int OSScan::os_scan_ipv4(vector<Target *> &Targets) {
  int itry = 0;
  /* Hosts which haven't matched and have been removed from incompleteHosts because
   * they have exceeded the number of retransmissions the host is allowed. */
  list<HostOsScanInfo *> unMatchedHosts; ///记录超时或超过最大重传而未匹配的主机扫描信息
 
  /* Check we have at least one target*/
  if (Targets.size() == 0) {
    return OP_FAILURE;
  }
 
  perf.init();///初始化扫描性能变量
 
  ///操作系统扫描的管理对象，维护未完成扫描列表std::list<HostOsScanInfo *> incompleteHosts;
  OsScanInfo OSI(Targets);
  if (OSI.numIncompleteHosts() == 0) {
    /* no one will be scanned */
    return OP_FAILURE;
  }
  ///设置起始时间与超时
  OSI.starttime = o.TimeSinceStart();
  startTimeOutClocks(&OSI);
 
  ///创建HOS对象，负责管理单个主机的具体扫描过程
  HostOsScan HOS(Targets[0]);
 
  /* Initialize the pcap session handler in HOS */
  ///打开libpcap，设置对应的BPF filter，以便接收目标的回复包
  begin_sniffer(&HOS, Targets);
  while (OSI.numIncompleteHosts() != 0) {
    if (itry > 0)
      sleep(1);
    if (itry == 3)
      usleep(1500000); /* Try waiting a little longer just in case it matters */
    if (o.verbose) {
      char targetstr[128];
      bool plural = (OSI.numIncompleteHosts() != 1);
      if (!plural) {
	(*(OSI.incompleteHosts.begin()))->target->NameIP(targetstr, sizeof(targetstr));
      } else Snprintf(targetstr, sizeof(targetstr), "%d hosts", (int) OSI.numIncompleteHosts());
      log_write(LOG_STDOUT, "%s OS detection (try #%d) against %s\n", (itry == 0)? "Initiating" : "Retrying", itry + 1, targetstr);
      log_flush_all();
    }
    ///准备第itry轮的OS探测：删除陈旧信息、初始化必要变量
    startRound(&OSI, &HOS, itry);
    ///执行顺序产生测试（发送6个TCP探测包，每隔100ms一个）
    doSeqTests(&OSI, &HOS);
    ///执行TCP/UDP/ICMP探测包测试
    doTUITests(&OSI, &HOS);
    ///对该轮探测的结果做指纹对比，获取OS扫描信息
    endRound(&OSI, &HOS, itry);
    ///将超时未匹配的主机移动到unMatchedHosts列表中
    expireUnmatchedHosts(&OSI, &unMatchedHosts);
    itry++;
  }
 
  /* Now move the unMatchedHosts array back to IncompleteHosts */
  ///对没有找到匹配的主机，将之移动的未完成列表，并查找出最接近的指纹（以概率形式展现给用户）
  if (!unMatchedHosts.empty())
    OSI.incompleteHosts.splice(OSI.incompleteHosts.begin(), unMatchedHosts);
 
  if (OSI.numIncompleteHosts()) {
    /* For hosts that don't have a perfect match, find the closest fingerprint
     * in the DB and, if we are in debugging mode, print them. */
    findBestFPs(&OSI);
    if (o.debugging > 1)
      printFP(&OSI);
  }
 
  return OP_SUCCESS;
}
```

