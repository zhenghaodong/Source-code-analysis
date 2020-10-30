# Nmap脚本引擎

## 原理

NSE(Nmap Scripting Engine)包含两个部分：Lua解释器和NSE Library。

## 框架

* nse_main.cc/nse_main.h/nse_main.lua是核心流程文件，负责脚本的初始化与调度执行

* nmap/nse_*文件，nmap源码目录下以nse开头的文件负责为NSE提供调用库
* liblua目录，提供Lua语言默认的源码C语言文件
* nselib目录，Nmap实现的NSE库文件，以Lua语言形式提供基本的库函数
* scripts目录，Nmap内置的实用脚本，即对具体扫描任务相关的操作脚本

## 流程

NSE初始化流程：

1. 设置随机种子
2. 床架Lua_State，用于管理Lua程序执行过程
3. 调用init_main()完成详细的初始化流程
4. 加载Lua所需要的函数表
5. 加载nse_main.lua脚本并设置相应的参数
6. 执行nse_main.lua文件进行配置过程
7. 将use_main.lua的main函数保存到Lua注册表

脚本扫描流程

1. 设置全局扫描类型状态
2. 清空栈区
3. 调用run_main执行详细的扫描过程
4. 清空栈区并创建主机组
5. 将主机列表与扫描阶段压入栈区，作为参数
6. 调用nse_main.lua中的main函数进行扫描

```c
///L_NSE用于保存Lua程序的状态
static lua_State *L_NSE = NULL;
 
///open_nse用于创建Lua状态，准备Lua解释器环境
///调用init_main()完成初始化操作。
void open_nse (void)
{
  if (L_NSE == NULL)    ///全局维护一份Lua状态
  {
    /*
     Set the random seed value on behalf of scripts.  Since Lua uses the
     C rand and srand functions, which have a static seed for the entire
     program, we don't want scripts doing this themselves.
     */
    srand(get_random_uint());
 
    ///创建Lua状态机，用于管理整个Lua程序的执行
    if ((L_NSE = luaL_newstate()) == NULL)
      fatal("%s: failed to open a Lua state!", SCRIPT_ENGINE);
    lua_atpanic(L_NSE, panic);  ///注册发生严重故障的回调函数为panic函数
 
#if 0
    /* Lua 5.2 */
    lua_pushcfunction(L_NSE, init_main);
    lua_pushlightuserdata(L_NSE, &o.chosenScripts);
    if (lua_pcall(L_NSE, 1, 0, 0))
#else
    ///此处lua_cpcall()以保护模式执行C语言函数init_main()
    if (lua_cpcall(L_NSE, init_main, &o.chosenScripts))
#endif
      fatal("%s: failed to initialize the script engine:\n%s\n", SCRIPT_ENGINE, 
          lua_tostring(L_NSE, -1));
  }
}
///scipt_scan函数具体执行脚本扫描的过程
///设置扫描状态；调用run_main()函数执行具体脚本扫描过程。
void script_scan (std::vector<Target *> &targets, stype scantype)
{
  ///设置全局的扫描状态为此处状态（可能是SCRIPT_PRE_SCAN/SCRIPT_SCAN/SCRIPT_POST_SCAN）
  o.current_scantype = scantype;
 
  ///断言L_NSE非空，并清空栈区（C与Lua调用交互过程均会在栈内完成）
  assert(L_NSE != NULL);
  lua_settop(L_NSE, 0); /* clear the stack */
 
#if 0
  /* Lua 5.2 */
  lua_pushcfunction(L_NSE, run_main);
  lua_pushlightuserdata(L_NSE, &targets);
  if (lua_pcall(L_NSE, 1, 0, 0))
#else
  ///此处lua_cpcall()以保护模式执行C语言函数run_main()
  if (lua_cpcall(L_NSE, run_main, &targets))
#endif
    error("%s: Script Engine Scan Aborted.\nAn error was thrown by the "
          "engine: %s", SCRIPT_ENGINE, lua_tostring(L_NSE, -1));
}
 
void close_nse (void)
{
  ///关闭Lua状态
  if (L_NSE != NULL)
  {
    lua_close(L_NSE);
    L_NSE = NULL;
  }
}
 
static int init_main (lua_State *L)
{
  char path[MAXPATHLEN];
  std::vector<std::string> *rules = (std::vector<std::string> *)
      lua_touserdata(L, 1);
 
  /* Load some basic libraries */
  luaL_openlibs(L);       ///加载Lua自身的库
  set_nmap_libraries(L);  ///加载Nmap扩展的Lua库
 
  lua_newtable(L);
  lua_setfield(L, LUA_REGISTRYINDEX, NSE_CURRENT_HOSTS);
 
  /* Load debug.traceback for collecting any error tracebacks */
  lua_settop(L, 0); /* clear the stack */
  lua_getglobal(L, "debug");
  lua_getfield(L, -1, "traceback");
  lua_replace(L, 1); // debug.traceback stack position 1
  lua_pushvalue(L, 1);
  lua_setfield(L, LUA_REGISTRYINDEX, NSE_TRACEBACK); /* save copy */
 
  /* Load main Lua code, stack position 2 */
  ///将nse_main.lua文件加载进来，文件被转换为匿名函数（栈索引为2），后续调用lua_pcall()执行它。
  if (nmap_fetchfile(path, sizeof(path), "nse_main.lua") != 1)
    luaL_error(L, "could not locate nse_main.lua");
  if (luaL_loadfile(L, path) != 0)
    luaL_error(L, "could not load nse_main.lua: %s", lua_tostring(L, -1));
 
  /* The first argument to the NSE Main Lua code is the private nse
   * library table which exposes certain necessary C functions to
   * the Lua engine.
   */
  ///加载提供给nse_main.lua调用的C语言函数表（栈索引为3）
  open_cnse(L); // stack index 3
 
  /* The second argument is the script rules, including the
   * files/directories/categories passed as the userdata to this function.
   */
  ///将脚本规则作为参数压入栈区（栈索引为4）
  lua_createtable(L, rules->size(), 0); // stack index 4
  for (std::vector<std::string>::iterator si = rules->begin();
       si != rules->end(); si++)
  {
    lua_pushstring(L, si->c_str());
    lua_rawseti(L, 4, lua_objlen(L, 4) + 1);
  }
 
  /* Get Lua main function */
  ///调用由nse_main.lua转换后的匿名函数（栈索引2）：
  ///传入2个参数（栈索引3/4），输出1个结果（执行完毕后放在栈顶），
  ///错误处理函数对应的栈区索引为1（即debug.traceback）。
  ///功能：在nse_main.lua会加载用户选择的所有的脚本，并初始化Script/Thread类
  if (lua_pcall(L, 2, 1, 1) != 0) lua_error(L); /* we wanted a traceback */
 
  ///将执行nse_main.lua返回的结果（nse_main.lua中的main函数对象）放入注册表中，
  ///以便后续的脚本扫描过程直接调用此main函数。
  lua_setfield(L, LUA_REGISTRYINDEX, NSE_MAIN);
  return 0;
}
 
static int run_main (lua_State *L)
{
  std::vector<Target *> *targets = (std::vector<Target*> *)
      lua_touserdata(L, 1);
 
  lua_settop(L, 0); ///清空栈区
 
  /* New host group */
  lua_newtable(L);  ///清空当前主机组
  lua_setfield(L, LUA_REGISTRYINDEX, NSE_CURRENT_HOSTS);
  
  ///读出error traceback函数
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_TRACEBACK); /* index 1 */
  
  ///获取nse_main.lua中的main()函数
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_MAIN); /* index 2 */
  assert(lua_isfunction(L, -1));  ///若不是函数，那此处必然有错
 
  /* The first and only argument to main is the list of targets.
   * This has all the target names, 1-N, in a list.
   */
  ///main (hosts, scantype)
  ///main函数需要两个参数，被扫描的主机组与扫描类型（PRE/SCRIPT/POST）
  ///以下代码将逐次加入等待扫描主机到NSE_CURRENT_HOSTS表中
  lua_createtable(L, targets->size(), 0); // stack index 3
  lua_getfield(L, LUA_REGISTRYINDEX, NSE_CURRENT_HOSTS); /* index 4 */
  for (std::vector<Target *>::iterator ti = targets->begin();
       ti != targets->end(); ti++)
  {
    Target *target = (Target *) *ti;
    const char *TargetName = target->TargetName();
    const char *targetipstr = target->targetipstr();
    lua_newtable(L);
    set_hostinfo(L, target);
    lua_rawseti(L, 3, lua_objlen(L, 3) + 1);
    if (TargetName != NULL && strcmp(TargetName, "") != 0)
      lua_pushstring(L, TargetName);
    else
      lua_pushstring(L, targetipstr);
    lua_pushlightuserdata(L, target);
    lua_rawset(L, 4); /* add to NSE_CURRENT_HOSTS */
  }
  lua_pop(L, 1); /* pop NSE_CURRENT_HOSTS */
 
  ///设置main()第二个参数，扫描类型
  /* push script scan type phase */
  switch (o.current_scantype)
  {
    case SCRIPT_PRE_SCAN:
      lua_pushstring(L, NSE_PRE_SCAN);
      break;
    case SCRIPT_SCAN:
      lua_pushstring(L, NSE_SCAN);
      break;
    case SCRIPT_POST_SCAN:
      lua_pushstring(L, NSE_POST_SCAN);
      break;
    default:
      fatal("%s: failed to set the script scan phase.\n", SCRIPT_ENGINE);
  }
 
  ///以保护模式运行main()函数，两个参数，0个返回值，错误处理函数在栈区的index1位置
  if (lua_pcall(L, 2, 0, 1) != 0) lua_error(L); /* we wanted a traceback */
  return 0;
}
```