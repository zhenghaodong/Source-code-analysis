# Nmap服务版本扫描分析

## 扫描原理

服务指纹对比匹配，对目标端口进行连接通信，产生当前端口的服务指纹，再与指纹数据库进行匹配对比，寻找匹配的服务类型。

**步骤**：

* 检查当前端口是否在排除端口列表内，如果存在则将端口剔除；
* tcp端口则尝试tcp连接，nmap将收到的banner信息与nmap-services-probes中NULLprobe的签名进行对比；
* 如果通过连接时的welcome banner无法确定服务版本，则尝试发送其他探测包，将probe得到回复包与数据库中的签名进行对比；若反复探测都无法得到具体应用，那么打印出应用返回报文供用户自行判定；
* 如果是udp端口则直接使用map-services-probes中的探测包进行探测匹配，根据结果对比分析udp应用服务类型；
* 如果探测到的程序为SSL，那么调用openSSL进一步查看运行在SSL之上的具体应用类型；
* 如果探测到的应用程序为SunRPC，那么调用brute-forceRPC grinder进一步探测具体服务。

## 框架

### ServiceGroup

用于管理一组目标机进行服务扫描的信息，如单个服务扫描信息、全部探测包信息、服务探测包信息等。

* 扫描完成的服务列表services_finished，记录目前已经扫描完毕的服务。
* 正在扫描的服务列表services_in_progress。多个服务可能在同时并发地被探测，所以此处将当前正在扫描的服务全部记录在该列表中。
* 剩余服务列表services_remaining，当前还没有开始探测的服务被放置在该列表中。在服务扫描初始化时，所有的服务的都被放置在列表中。
* 最大的并发探测包ideal_parallelism，用于确定同时发送服务探测包的并发数量，此值取决于用户配置的时序参数和具体网卡的支持能力等因素。若配置时序为-T4，那么会将ideal_parallelism设置40。
* 扫描进度测量器ScanProgressMeter，用于记录服务扫描的进度情况，以便能够实时地反馈给用户。在控制台界面按下普通按键（如按下空格键，不包括“vVdDp?”字符，这几个字符有特殊含义），Nmap会打印出当前的扫描进度。
* 超时主机的数量，记录当前扫描超时的主机数量。

```c
// This holds the service information for a group of Targets being service scanned.
class ServiceGroup {
public:
  ServiceGroup(vector<Target *> &Targets, AllProbes *AP);
  ~ServiceGroup();
  list<ServiceNFO *> services_finished; // Services finished (discovered or not)
  list<ServiceNFO *> services_in_progress; // Services currently being probed
  list<ServiceNFO *> services_remaining; // Probes not started yet
  unsigned int ideal_parallelism; // Max (and desired) number of probes out at once.
  ScanProgressMeter *SPM;
  int num_hosts_timedout; // # of hosts timed out during (or before) scan
};
```

### ServiceNFO

负责管理特定的服务和探测细节，ServiceGroup就是管理ServiceNFO对象的列表。

ServiceNFO包含以下信息：

* 服务指纹管理
* 服务扫描对应主机
* 服务探测匹配信息
* 管理探测包
* 管理回复包
* 服务扫描所需的全部探测包AllProbes *AP

### Allprobes

负责管理全部的服务探测包(Probes)，该类的对象从nmap-service-probes数据库文件中解析出探测包及匹配方式等信息并管理起来。在后续服务扫描时在此对象中来按需取出探测包发送即可。Allprobes包含以下信息：

* 探测包管理
* 编制回退数组，当回复包无法匹配当前字符时，允许回退到上一个字符串
* 管理排除端口列表。在nmap-service-probes中指定需排除的服务扫描，默认排除TCP的9100-9107端口，此类打印机服务会返回大量的无用信息
* 服务初始化接口与释放接口

```c
class AllProbes {
public:
  AllProbes();
  ~AllProbes();
  // Tries to find the probe in this AllProbes class which have the
  // given name and protocol.  It can return the NULL probe.
  ServiceProbe *getProbeByName(const char *name, int proto);
  std::vector<ServiceProbe *> probes; // All the probes except nullProbe
  ServiceProbe *nullProbe; // No probe text - just waiting for banner

  // Before this function is called, the fallbacks exist as unparsed
  // comma-separated strings in the fallbackStr field of each probe.
  // This function fills out the fallbacks array in each probe with
  // an ordered list of pointers to which probes to try. This is both for
  // efficiency and to deal with odd cases like the NULL probe and falling
  // back to probes later in the file. This function also free()s all the
  // fallbackStrs.
  void compileFallbacks();

  int isExcluded(unsigned short port, int proto);
  bool excluded_seen;
  struct scan_lists excludedports;
  
  static AllProbes *service_scan_init(void);
  static void service_scan_free(void);
  static int check_excluded_port(unsigned short port, int proto);
protected:
  static AllProbes *global_AP;
};
```

### ServiceProbe

负责管理单个的服务探测包详细信息。具体信息来自于nmap-service-probes数据库文件，AllProbes类在初始化时会读取该文件，并依据其每个探测信息创建ServiceProbe对象，放置在AllProbes内部的向量std::vector<ServiceProbe *>probes中。主要包含以下内容：

* 探测包名字
* 探测包字符串及字符串长度
* 允许的端口及SSL端口
* 探测包的协议类型
* 可被探测的服务类型
* 服务探测包匹配管理
* 探测回退数组
* 测试是否匹配
* 其他接口函数

### ServiceProbeMatch

用于管理特定的服务探测包的匹配信息（match）。nmap-service-probes文件中每一个match和softmatch行都对应到该类的对象。主要包含以下内容：

* 探测包匹配详细信息
* 探测匹配情况
* 测试是否匹配接口函数

```c
class ServiceProbeMatch {
 public:
  ServiceProbeMatch();
  ~ServiceProbeMatch();

// match text from the nmap-service-probes file.  This must be called
// before you try and do anything with this match.  This function
// should be passed the whole line starting with "match" or
// "softmatch" in nmap-service-probes.  The line number that the text
// is provided so that it can be reported in error messages.  This
// function will abort the program if there is a syntax problem.
  void InitMatch(const char *matchtext, int lineno);

  // If the buf (of length buflen) match the regex in this
  // ServiceProbeMatch, returns the details of the match (service
  // name, version number if applicable, and whether this is a "soft"
  // match.  If the buf doesn't match, the serviceName field in the
  // structure will be NULL.  The MatchDetails returned is only valid
  // until the next time this function is called.  The only exception
  // is that the serviceName field can be saved throughought program
  // execution.  If no version matched, that field will be NULL.
  const struct MatchDetails *testMatch(const u8 *buf, int buflen);
// Returns the service name this matches
  const char *getName() { return servicename; }
  // The Line number where this match string was defined.  Returns
  // -1 if unknown.
  int getLineNo() { return deflineno; }
 private:
  int deflineno; // The line number where this match is defined.
  bool isInitialized; // Has InitMatch yet been called?
  char *servicename;
  int matchtype; // SERVICEMATCH_REGEX or SERVICESCAN_STATIC
  char *matchstr; // Regular expression text, or static string
  int matchstrlen; // Because static strings may have embedded NULs
  pcre *regex_compiled;
  pcre_extra *regex_extra;
  bool matchops_ignorecase;
  bool matchops_dotall;
  bool isSoft; // is this a soft match? ("softmatch" keyword in nmap-service-probes)
  // If any of these 3 are non-NULL, a product, version, or template
  // string was given to deduce the application/version info via
  // substring matches.
  char *product_template;
  char *version_template;
  char *info_template;
  // More templates:
  char *hostname_template;
  char *ostype_template;
  char *devicetype_template;
  std::vector<char *> cpe_templates;
  // The anchor is for SERVICESCAN_STATIC matches.  If the anchor is not -1, the match must
  // start at that zero-indexed position in the response str.
  int matchops_anchor;
// Details to fill out and return for testMatch() calls
  struct MatchDetails MD_return;

  // Use the six version templates and the match data included here
  // to put the version info into the given strings, (as long as the sizes
  // are sufficient).  Returns zero for success.  If no template is available
  // for a string, that string will have zero length after the function
  // call (assuming the corresponding length passed in is at least 1)
  int getVersionStr(const u8 *subject, int subjectlen, int *ovector, 
		  int nummatches, char *product, int productlen,
		  char *version, int versionlen, char *info, int infolen,
                  char *hostname, int hostnamelen, char *ostype, int ostypelen,
                  char *devicetype, int devicetypelen,
                  char *cpe_a, int cpe_alen,
                  char *cpe_h, int cpe_hlen,
                  char *cpe_o, int cpe_olen);
};
```

## 流程

* 解析出服务侦测使用的探测包(ALLProbes)
* 创建服务组提取目标端口中的open、open|filtered端口
* 移除被排除的端口
* 创建nsock pool使用nsock库
* 设置version trace跟踪服务扫描过程细节
* 若有SSL，将其配置为最大速度
* 发起服务探测包开始服务与版本扫描
* 获取当前时间
* 进入nsock循环
* 退出nsock循环，删除nsock pool
* 打印信息处理结果

```c

/* Execute a service fingerprinting scan against all open ports of the
   Targets specified. */
///针对指定目标机的开放的端口进行服务指纹扫描，
///此处会用到Nmap的nsock库（并发的Socket Event处理库）
int service_scan(vector<Target *> &Targets) {
  // int service_scan(Target *targets[], int num_targets)
  AllProbes *AP;
  ServiceGroup *SG;
  nsock_pool nsp;
  struct timeval now;
  int timeout;
  enum nsock_loopstatus looprc;
  struct timeval starttv;
 
  if (Targets.size() == 0)
    return 1;
 
  AP = AllProbes::service_scan_init();///获取AllProbes对象,AllProbes仅维护一个Static对象
  ///在service_scan_init()中将读取nmap-service-probes文件，解析出需要的探测包,并存放在
  ///AllProbes中std::vector<ServiceProbe *> probes向量中。
 
 
  // Now I convert the targets into a new ServiceGroup
  ///使用Targets向量与AllProbes创建服务组ServiceGroup,从Targets中提取open端口及
  ///open|filtered端口，放入services_remaining等待进行服务扫描。
  ///在创建服务组时，确定出服务扫描的最佳并发度ideal_parallelism
  SG = new ServiceGroup(Targets, AP);
 
  if (o.override_excludeports) {
    ///覆盖被排除端口，当命令行中指定--all-ports时会走到此分支。
    ///被排除的端口是指在nmap-service-probes文件用Exclude指令定义的端口。
    if (o.debugging || o.verbose) log_write(LOG_PLAIN, "Overriding exclude ports option! Some undesirable ports may be version scanned!\n");
  } else {
    ///从ServiceGroup中移除被排除的端口,Nmap默认会排出掉9100-9107与打印机相关的服务，
    ///因为此类服务只是简单返回Nmap发送过去的探测包，会产生大量的垃圾的流量。
    ///默认情况下在nmap-service-probes文件头部定义：Exclude T:9100-9107
    remove_excluded_ports(AP, SG);
  }
  ///为所有需要进行服务扫描的主机设置超时值
  startTimeOutClocks(SG);
 
  if (SG->services_remaining.size() == 0) {
    delete SG;
    return 1;
  }
  
  gettimeofday(&starttv, NULL);
  if (o.verbose) {
    char targetstr[128];
    bool plural = (Targets.size() != 1);
    if (!plural) {
      (*(Targets.begin()))->NameIP(targetstr, sizeof(targetstr));
    } else Snprintf(targetstr, sizeof(targetstr), "%u hosts", (unsigned) Targets.size());
 
    log_write(LOG_STDOUT, "Scanning %u %s on %s\n", 
	      (unsigned) SG->services_remaining.size(), 
	      (SG->services_remaining.size() == 1)? "service" : "services", 
	      targetstr);
  }
 
  // Lets create a nsock pool for managing all the concurrent probes
  // Store the servicegroup in there for availability in callbacks
  ///创建nsock pool，以使用nsock并发控制探测包
  if ((nsp = nsp_new(SG)) == NULL) {
    fatal("%s() failed to create new nsock pool.", __func__);
  }
 
  ///根据用户指定的packettrace配置，设置nsock的trace级别
  if (o.versionTrace()) {
    nsp_settrace(nsp, NULL, NSOCK_TRACE_LEVEL, o.getStartTime());
  }
 
#if HAVE_OPENSSL
  /* We don't care about connection security in version detection. */
  ///配置SSL时，关注传输速度，而不关注安全性本身，以加速服务扫描过程。
  nsp_ssl_init_max_speed(nsp);
#endif
 
  ///从service_remaining列表中找出满足条件的等待探测服务，对之进行配置，
  ///创建nsock文件描述符(niod)，并通过nsock建立连接（如nsock_connect_tcp()），
  ///并将此探测服务移动到services_in_progress列表中。
  launchSomeServiceProbes(nsp, SG);
 
  // How long do we have before timing out?
  gettimeofday(&now, NULL);
  timeout = -1;
 
  // OK!  Lets start our main loop!
  ///nsock主循环，在此循环内处理各种探测包的事件(nsock event)
  ///在上述的launchSomeServiceProbes操作中，调用到nsock_connect_tcp/udp/sctp等，
  ///最终执行nsp_add_event函数向nsock pool添加等待处理的事件。
  looprc = nsock_loop(nsp, timeout);
  if (looprc == NSOCK_LOOP_ERROR) {
    int err = nsp_geterrorcode(nsp);
    fatal("Unexpected nsock_loop error.  Error code %d (%s)", err, strerror(err));
  }
  ///退出主循环后，删除nsock pool
  nsp_delete(nsp);
 
  if (o.verbose) {
    char additional_info[128];
    if (SG->num_hosts_timedout == 0)
      Snprintf(additional_info, sizeof(additional_info), "%u %s on %u %s",
		(unsigned) SG->services_finished.size(),  
		(SG->services_finished.size() == 1)? "service" : "services", 
		(unsigned) Targets.size(), (Targets.size() == 1)? "host" : "hosts");
    else Snprintf(additional_info, sizeof(additional_info), "%u %s timed out", 
		   SG->num_hosts_timedout, 
		   (SG->num_hosts_timedout == 1)? "host" : "hosts");
    SG->SPM->endTask(NULL, additional_info);
  }
 
  // Yeah - done with the service scan.  Now I go through the results
  // discovered, store the important info away, and free up everything
  // else.
  ///对服务扫描结果的处理
  processResults(SG);
  delete SG;
  return 0;
}
```