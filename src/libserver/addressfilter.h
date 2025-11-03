#ifndef ADDRESSFILTER_H
#define ADDRESSFILTER_H

#include "eibtypes.h"
#include <bitset>
#include <string>
#include "inifile.h"
#include "link.h"
#include "lowlevel.h"
#include "lpdu.h"

// 物理地址最大数量: 16*16*256 = 65536
#define MAX_PHYSICAL_ADDRESSES 65536
// 组地址最大数量: 65535
#define MAX_GROUP_ADDRESSES 65536

// 使用 FILTER 宏声明类，绑定名称 "address"
FILTER(AddressFilter, address)
{
public:
    // 构造函数（参数需与基类 Filter 一致）
    AddressFilter(const LinkConnectPtr_ &c, IniSectionPtr &s);
    virtual ~AddressFilter();

    // 重写接收和发送过滤方法
    virtual bool setup();
    virtual void send_L_Data(LDataPtr l);
    virtual void recv_L_Data(LDataPtr l);
    virtual void send_Next();

    virtual void start();
    virtual void started();
    virtual void stopped(bool err);

    virtual void recv_L_Busmonitor(LBusmonPtr l);

    /** ask the system whether it knows this indiv address */
    virtual bool checkSysAddress(eibaddr_t addr);

    /** ask the system whether it knows this group address */
    virtual bool checkSysGroupAddress(eibaddr_t addr);

    /** remove this object from the chain */
    virtual void unlink();

private:
    // 地址解析方法
    eibaddr_t parsePhysicalAddress(const std::string &addr);
    std::vector<std::string> parseScopeGroupAddress(const std::string &addr);
    eibaddr_t parseGroupAddress(const std::string &addr);

    // 解析支线地址（如"1.2"表示1.2.x的所有地址）
    void parsePhysicalLineAddress(const std::string &addr, bool isUpstream, bool isAllow);

    // 解析配置
    void parseConfig(IniSectionPtr config);

    // 地址检查方法
    bool checkUpstreamPhysicalAddress(eibaddr_t physAddr);
    bool checkDownstreamPhysicalAddress(eibaddr_t physAddr);
    bool checkGroupAddress(eibaddr_t groupAddr);

private:
    // 物理地址过滤规则（上行：接收方向，下行：发送方向）
    std::bitset<MAX_PHYSICAL_ADDRESSES> allowPhysicalUp_;   // 上行允许
    std::bitset<MAX_PHYSICAL_ADDRESSES> denyPhysicalUp_;    // 上行拒绝
    std::bitset<MAX_PHYSICAL_ADDRESSES> allowPhysicalDown_; // 下行允许
    std::bitset<MAX_PHYSICAL_ADDRESSES> denyPhysicalDown_;  // 下行拒绝

    // 组地址过滤规则（不分上下行）
    std::bitset<MAX_GROUP_ADDRESSES> allowGroup_;
    std::bitset<MAX_GROUP_ADDRESSES> denyGroup_;
};

#endif // ADDRESSFILTER_H