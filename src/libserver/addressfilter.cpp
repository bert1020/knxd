#include "addressfilter.h"
#include "common.h"
#include "error.h"
#include <sstream>
#include <cstring>

// 实现构造函数
AddressFilter::AddressFilter(const LinkConnectPtr_ &c, IniSectionPtr &s)
    : Filter(c, s)
{
    parseConfig(s);
    TRACEPRINTF(t, 0, "AddressFilter (FILTER macro) initialized");
}

AddressFilter::~AddressFilter()
{
}

// 解析配置
void AddressFilter::parseConfig(IniSectionPtr config)
{
    // 解析上行物理地址规则
    std::string allowPhysUp = config->value("allow-physical-up", "");
    std::istringstream issPhysUp(allowPhysUp);
    std::string addr;
    while (std::getline(issPhysUp, addr, ','))
    {
        if (!addr.empty())
        {
            try
            {
                // 检查是否是支线地址（格式X.Y）
                if (addr.find('.') != std::string::npos && addr.find('.', addr.find('.') + 1) == std::string::npos)
                {
                    parsePhysicalLineAddress(addr, true, true);
                }
                else
                {
                    eibaddr_t phys = parsePhysicalAddress(addr);
                    allowPhysicalUp_.set(phys);
                    TRACEPRINTF(t, 0, "Allow upstream physical: %s", addr.c_str());
                }
            }
            catch (...)
            {
                ERRORPRINTF(t, E_WARNING, "Invalid upstream physical address: %s", addr.c_str());
            }
        }
    }

    std::string denyPhysUp = config->value("deny-physical-up", "");
    std::istringstream issDenyPhysUp(denyPhysUp);
    while (std::getline(issDenyPhysUp, addr, ','))
    {
        if (!addr.empty())
        {
            try
            {
                if (addr.find('.') != std::string::npos && addr.find('.', addr.find('.') + 1) == std::string::npos)
                {
                    parsePhysicalLineAddress(addr, true, false);
                }
                else
                {
                    eibaddr_t phys = parsePhysicalAddress(addr);
                    denyPhysicalUp_.set(phys);
                    TRACEPRINTF(t, 0, "Deny upstream physical: %s", addr.c_str());
                }
            }
            catch (...)
            {
                ERRORPRINTF(t, E_WARNING, "Invalid upstream physical address: %s", addr.c_str());
            }
        }
    }

    // 解析下行物理地址规则
    std::string allowPhysDown = config->value("allow-physical-down", "");
    std::istringstream issPhysDown(allowPhysDown);
    while (std::getline(issPhysDown, addr, ','))
    {
        if (!addr.empty())
        {
            try
            {
                if (addr.find('.') != std::string::npos && addr.find('.', addr.find('.') + 1) == std::string::npos)
                {
                    parsePhysicalLineAddress(addr, false, true);
                }
                else
                {
                    eibaddr_t phys = parsePhysicalAddress(addr);
                    allowPhysicalDown_.set(phys);
                    TRACEPRINTF(t, 0, "Allow downstream physical: %s", addr.c_str());
                }
            }
            catch (...)
            {
                ERRORPRINTF(t, E_WARNING, "Invalid downstream physical address: %s", addr.c_str());
            }
        }
    }

    std::string denyPhysDown = config->value("deny-physical-down", "");
    std::istringstream issDenyPhysDown(denyPhysDown);
    while (std::getline(issDenyPhysDown, addr, ','))
    {
        if (!addr.empty())
        {
            try
            {
                if (addr.find('.') != std::string::npos && addr.find('.', addr.find('.') + 1) == std::string::npos)
                {
                    parsePhysicalLineAddress(addr, false, false);
                }
                else
                {
                    eibaddr_t phys = parsePhysicalAddress(addr);
                    denyPhysicalDown_.set(phys);
                    TRACEPRINTF(t, 0, "Deny downstream physical: %s", addr.c_str());
                }
            }
            catch (...)
            {
                ERRORPRINTF(t, E_WARNING, "Invalid downstream physical address: %s", addr.c_str());
            }
        }
    }

    // 解析组地址规则（不分上下行）
    std::string allowGrp = config->value("allow-group", "");
    std::istringstream issGrp(allowGrp);
    while (std::getline(issGrp, addr, ','))
    {
        if (!addr.empty())
        {

            std::vector<std::string> grpAddrs = parseScopeGroupAddress(addr);
            for (const auto &addrNew : grpAddrs)
            {
                try
                {
                    eibaddr_t grp = parseGroupAddress(addrNew);
                    allowGroup_.set(grp);
                    TRACEPRINTF(t, 0, "Allow group: %s", addrNew.c_str());
                }
                catch (...)
                {
                    ERRORPRINTF(t, E_WARNING, "Invalid group address: %s", addrNew.c_str());
                }
            }
            // try
            // {
            //     eibaddr_t grp = parseGroupAddress(addr);
            //     allowGroup_.set(grp);
            //    TRACEPRINTF(t,0, "Allow group: %s", addr.c_str());
            // }
            // catch (...)
            // {
            //    TRACEPRINTF(t,0, "Invalid group address: %s", addr.c_str());
            //     ERRORPRINTF(t, E_WARNING, "Invalid group address: %s", addr.c_str());
            // }
        }
    }

    std::string denyGrp = config->value("deny-group", "");
    std::istringstream issDenyGrp(denyGrp);
    while (std::getline(issDenyGrp, addr, ','))
    {
        if (!addr.empty())
        {
            std::vector<std::string> grpAddrs = parseScopeGroupAddress(addr);
            for (const auto &addrNew : grpAddrs)
            {
                try
                {
                    eibaddr_t grp = parseGroupAddress(addrNew);
                    denyGroup_.set(grp);
                    TRACEPRINTF(t, 0, "Deny group: %s", addrNew.c_str());
                }
                catch (...)
                {
                    ERRORPRINTF(t, E_WARNING, "Invalid group address: %s", addrNew.c_str());
                }
            }
            // try {
            //     eibaddr_t grp = parseGroupAddress(addr);
            //     denyGroup_.set(grp);
            //    TRACEPRINTF(t,0, "Deny group: %s", addr.c_str());
            // } catch (...) {
            //    TRACEPRINTF(t,0, "Invalid group address: %s", addr.c_str());
            //     ERRORPRINTF(t, E_WARNING, "Invalid group address: %s", addr.c_str());
            // }
        }
    }
}

// 解析支线地址（如"1.2"表示1.2.x的所有地址）
void AddressFilter::parsePhysicalLineAddress(const std::string &addr, bool isUpstream, bool isAllow)
{
    int a, b;
    if (sscanf(addr.c_str(), "%d.%d", &a, &b) != 2)
    {
        throw std::invalid_argument("Invalid line address (X.Y)");
    }
    if (a < 0 || a > 15 || b < 0 || b > 15)
    {
        throw std::invalid_argument("Line address out of range");
    }

    // 计算支线起始地址和结束地址
    eibaddr_t startAddr = ((a & 0x0F) << 12) | ((b & 0x0F) << 8);
    eibaddr_t endAddr = startAddr | 0xFF;

    // 为支线内所有地址设置过滤规则
    for (eibaddr_t addr = startAddr; addr <= endAddr; ++addr)
    {
        if (isUpstream)
        {
            if (isAllow)
            {
                allowPhysicalUp_.set(addr);
            }
            else
            {
                denyPhysicalUp_.set(addr);
            }
        }
        else
        {
            if (isAllow)
            {
                allowPhysicalDown_.set(addr);
            }
            else
            {
                denyPhysicalDown_.set(addr);
            }
        }
    }
    TRACEPRINTF(t, 0, "%s upstream physical line: %s", isAllow ? "Allow" : "Deny", addr.c_str());
}

// 物理地址解析（与框架对齐）
eibaddr_t AddressFilter::parsePhysicalAddress(const std::string &addr)
{
    int a, b, c;
    if (sscanf(addr.c_str(), "%d.%d.%d", &a, &b, &c) != 3)
    {
        throw std::invalid_argument("Invalid physical address (X.Y.Z)");
    }
    if (a < 0 || a > 15 || b < 0 || b > 15 || c < 0 || c > 255)
    {
        throw std::invalid_argument("Physical address out of range");
    }
    return ((a & 0x0F) << 12) | ((b & 0x0F) << 8) | (c & 0xFF);
}

std::vector<std::string> AddressFilter::parseScopeGroupAddress(const std::string &addr)
{
    std::vector<std::string> results;

    // 按 '/' 分割字符串
    std::vector<std::string> parts;
    std::stringstream ss(addr);
    std::string token;

    while (std::getline(ss, token, '/'))
    {
        parts.push_back(token);
    }

    // 检查格式是否正确（至少需要3部分：X/Y/Z）
    if (parts.size() < 3)
    {
        throw std::invalid_argument("Invalid group address format (X/Y/Z)");
    }

    // 获取最后一部分
    std::string lastPart = parts.back();
    parts.pop_back(); // 移除最后一部分，保留前两部分

    // 检查最后一部分是否包含 '-'
    size_t dashPos = lastPart.find('-');
    if (dashPos == std::string::npos)
    {
        // 没有 '-'，直接返回原字符串
        results.push_back(addr);
        return results;
    }

    // 有 '-'，按 '-' 分割最后一部分
    std::string startStr = lastPart.substr(0, dashPos);
    std::string endStr = lastPart.substr(dashPos + 1);

    // 转换为数字
    int start, end;
    try
    {
        start = std::stoi(startStr);
        end = std::stoi(endStr);
    }
    catch (const std::exception &e)
    {
        throw std::invalid_argument("Invalid number format in range");
    }

    // 检查范围是否有效
    if (start > end)
    {
        throw std::invalid_argument("Start number cannot be greater than end number");
    }

    // 生成范围并拼接
    for (int i = start; i <= end; ++i)
    {
        std::stringstream resultStream;
        // 添加前两部分
        for (size_t j = 0; j < parts.size(); ++j)
        {
            resultStream << parts[j];
            if (j < parts.size() - 1)
            {
                resultStream << "/";
            }
        }
        // 添加当前数字
        if (!parts.empty())
        {
            resultStream << "/";
        }
        resultStream << i;

        results.push_back(resultStream.str());
    }

    return results;
}

// 组地址解析（与框架对齐）
eibaddr_t AddressFilter::parseGroupAddress(const std::string &addr)
{
    int a, b, c;
    if (sscanf(addr.c_str(), "%d/%d/%d", &a, &b, &c) != 3)
    {
        // t->TracePrintf (0, "===== parseGroupAddress error: %s", addr.c_str());
        throw std::invalid_argument("Invalid group address (X/Y/Z)");
    }
    if (a < 0 || a > 31 || b < 0 || b > 7 || c < 0 || c > 255)
    {
        // t->TracePrintf (0, "=====111 parseGroupAddress error: %s", addr.c_str());
        throw std::invalid_argument("Group address out of range");
    }
    return ((a & 0x1F) << 11) | ((b & 0x07) << 8) | (c & 0xFF);
}

// 上行物理地址检查（接收方向）
bool AddressFilter::checkUpstreamPhysicalAddress(eibaddr_t physAddr)
{
    TRACEPRINTF(t, 0, "Checking upstream physical address: %s", FormatEIBAddr(physAddr).c_str());

    // 先检查拒绝列表
    if (denyPhysicalUp_.test(physAddr))
    {
        TRACEPRINTF(t, 0, "Blocked upstream physical: %s", FormatEIBAddr(physAddr).c_str());
        return false;
    }

    // 允许列表为空则默认允许所有，否则只允许列表中的地址
    if (!allowPhysicalUp_.none() && !allowPhysicalUp_.test(physAddr))
    {
        TRACEPRINTF(t, 0, "Not allowed upstream physical: %s", FormatEIBAddr(physAddr).c_str());
        return false;
    }

    return true;
}

// 下行物理地址检查（发送方向）
bool AddressFilter::checkDownstreamPhysicalAddress(eibaddr_t physAddr)
{
    TRACEPRINTF(t, 0, "Checking downstream physical address: %s", FormatEIBAddr(physAddr).c_str());

    if (denyPhysicalDown_.test(physAddr))
    {
        TRACEPRINTF(t, 0, "Blocked downstream physical: %s", FormatEIBAddr(physAddr).c_str());
        return false;
    }

    if (!allowPhysicalDown_.none() && !allowPhysicalDown_.test(physAddr))
    {
        TRACEPRINTF(t, 0, "Not allowed downstream physical: %s", FormatEIBAddr(physAddr).c_str());
        return false;
    }

    return true;
}

// 组地址检查（不分上下行）
bool AddressFilter::checkGroupAddress(eibaddr_t groupAddr)
{
    TRACEPRINTF(t, 0, "Checking group address: %s", FormatGroupAddr(groupAddr).c_str());

    if (denyGroup_.test(groupAddr))
    {
        TRACEPRINTF(t, 0, "Blocked group: %s", FormatGroupAddr(groupAddr).c_str());
        return false;
    }

    if (!allowGroup_.none() && !allowGroup_.test(groupAddr))
    {
        TRACEPRINTF(t, 0, "Not allowed group: %s", FormatGroupAddr(groupAddr).c_str());
        return false;
    }

    return true;
}

// 接收过滤（下行）
void AddressFilter::recv_L_Data(LDataPtr l)
{
    TRACEPRINTF(t, 0, "AddressFilter::recv_L_Data(LDataPtr l) ");
    if (l->address_type == IndividualAddress)
    {
        eibaddr_t srcPhys = l->source_address;
        // 检查下行物理地址
        if (checkDownstreamPhysicalAddress(srcPhys))
        {
            Filter::recv_L_Data(std::move(l));
            return;
        }
    }
    else if (l->address_type == GroupAddress)
    {
        eibaddr_t groupAddr = l->destination_address;
        // 如果是组地址，检查组地址过滤规则
        if (checkGroupAddress(groupAddr))
        {
            Filter::recv_L_Data(std::move(l));
            return;
        }
    }
    TRACEPRINTF(t, 0, "AddressFilter::recv_L_Data(LDataPtr 2)");
}

// 发送过滤（上行）
void AddressFilter::send_L_Data(LDataPtr l)
{
    TRACEPRINTF(t, 0, "AddressFilter::send_L_Data(LDataPtr l   1)");

    if (l->address_type == IndividualAddress)
    {
        eibaddr_t srcPhys = l->source_address;
        // 检查上行物理地址
        if (checkUpstreamPhysicalAddress(srcPhys))
        {
            TRACEPRINTF(t, 0, "AddressFilter::send_L_Data(LDataPtr l  2)");
            Filter::send_L_Data(std::move(l));
            return;
        }
    }
    // 如果是组地址，检查组地址过滤规则
    else if (l->address_type == GroupAddress)
    {
        eibaddr_t groupAddr = l->destination_address;
        if (checkGroupAddress(groupAddr))
        {
            TRACEPRINTF(t, 0, "AddressFilter::send_L_Data(LDataPtr l 3)");
            Filter::send_L_Data(std::move(l));
            return;
        }
    }
    TRACEPRINTF(t, 0, "AddressFilter::send_L_Data(LDataPtr 2)");
    send_Next();
}

bool AddressFilter::setup()
{
    TRACEPRINTF(t, 0, "AddressFilter::setup()");
    if (!Filter::setup())
        return false;
    return true;
}

void AddressFilter::start()
{
    TRACEPRINTF(t, 0, "AddressFilter::start()");
    Filter::start();
}

void AddressFilter::started()
{
    TRACEPRINTF(t, 0, "AddressFilter::started()");
    Filter::started();
}

void AddressFilter::stopped(bool err)
{
    TRACEPRINTF(t, 0, "AddressFilter::stopped(bool err)");
    Filter::stopped(err);
}

void AddressFilter::send_Next()
{
    TRACEPRINTF(t, 0, "AddressFilter::send_Next()");
    Filter::send_Next();
}

void AddressFilter::recv_L_Busmonitor(LBusmonPtr l)
{
}

/** ask the system whether it knows this indiv address */
bool AddressFilter::checkSysAddress(eibaddr_t addr)
{
    return true;
}

/** ask the system whether it knows this group address */
bool AddressFilter::checkSysGroupAddress(eibaddr_t addr)
{
    return true;
}

/** remove this object from the chain */
void AddressFilter::unlink()
{
    TRACEPRINTF(t, 0, "void AddressFilter::unlink()");
}