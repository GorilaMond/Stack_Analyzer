// Copyright 2024 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: luiyanbing@foxmail.com
//
// 包装用于采集调用栈数据的eBPF程序，规定一些抽象接口和通用变量

#include "bpf_wapper/eBPFStackCollector.h"
#include "sa_user.h"
#include "dt_symbol.h"

#include <sstream>
#include <map>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

std::string getLocalDateTime(void)
{
    auto t = time(NULL);
    auto localTm = localtime(&t);
    char buff[32];
    strftime(buff, 32, "%Y%m%d_%H_%M_%S", localTm);
    return std::string(buff);
};

bool operator<(const CountItem a, const CountItem b)
{
    if (a.v[0] < b.v[0] || (a.v[0] == b.v[0] && a.k.pid < b.k.pid))
        return true;
    else
        return false;
}

StackCollector::StackCollector()
{
    self_tgid = getpid();
};

std::vector<CountItem> *StackCollector::sortedCountList(void)
{
    auto psid_count_map = bpf_object__find_map_by_name(obj, "psid_count_map");
    auto val_size = bpf_map__value_size(psid_count_map);
    auto value_fd = bpf_object__find_map_fd_by_name(obj, "psid_count_map");

    auto keys = new psid[MAX_ENTRIES];
    auto vals = new char[MAX_ENTRIES * val_size];
    uint32_t count = MAX_ENTRIES;
    psid next_key;
    int err;
    if (showDelta)
    {
        err = bpf_map_lookup_and_delete_batch(value_fd, NULL, &next_key, keys, vals, &count, NULL);
    }
    else
    {
        err = bpf_map_lookup_batch(value_fd, NULL, &next_key, keys, vals, &count, NULL);
    }
    if (err == EFAULT)
    {
        return NULL;
    }

    auto D = new std::vector<CountItem>();
    for (uint32_t i = 0; i < count; i++)
    {
        CountItem d(keys[i], count_values(vals + val_size * i));
        D->insert(std::lower_bound(D->begin(), D->end(), d), d);
    }
    delete[] keys;
    delete[] vals;
    return D;
};

StackCollector::operator std::string()
{
    std::ostringstream oss;
    oss << _RED "time:" << getLocalDateTime() << _RE "\n";
    std::map<int32_t, std::vector<std::string>> traces;
    std::map<uint32_t, task_info> infos;

    oss << _BLUE "counts:" _RE "\n";
    {
        auto D = sortedCountList();
        if (!D)
            return oss.str();
        if ((*D).size() > top)
        {
            auto end = (*D).end();
            auto begin = end - top;
            for (auto i = (*D).begin(); i < begin; i++)
                delete i->v;
            (*D).assign(begin, end);
        }
        oss << _GREEN "pid\tusid\tksid";
        for (int i = 0; i < scale_num; i++)
            oss << '\t' << scales[i].Type << "/" << scales[i].Period << scales[i].Unit;
        oss << _RE "\n";
        uint64_t trace[MAX_STACKS], *p;
        for (auto &i : *D)
        {
            auto &id = i.k;
            oss << id.pid << '\t' << id.usid << '\t' << id.ksid;
            {
                auto &v = i.v;
                for (int i = 0; i < scale_num; i++)
                    oss << '\t' << v[i];
                delete v;
            }
            oss << '\n';
            auto trace_fd = bpf_object__find_map_fd_by_name(obj, "sid_trace_map");
            if (id.usid > 0 && traces.find(id.usid) == traces.end())
            {
                bpf_map_lookup_elem(trace_fd, &id.usid, trace);
                for (p = trace + MAX_STACKS - 1; !*p; p--)
                    ;
                std::vector<std::string> sym_trace(p - trace + 1);
                for (int i = 0; p >= trace; p--)
                {
                    uint64_t &addr = *p;
                    symbol sym;
                    sym.reset(addr);
                    elf_file file;
                    if (g_symbol_parser.find_symbol_in_cache(id.pid, addr, sym.name))
                        ;
                    else if (g_symbol_parser.get_symbol_info(id.pid, sym, file) && g_symbol_parser.find_elf_symbol(sym, file, id.pid, id.pid))
                    {
                        if (sym.name[0] == '_' && sym.name[1] == 'Z')
                            // 代表是C++符号，则调用demangle解析
                            sym.name = demangleCppSym(sym.name);
                        std::stringstream ss("");
                        ss << "+0x" << std::hex << (sym.ip - sym.start);
                        sym.name += ss.str();
                        clearSpace(sym.name);
                        g_symbol_parser.putin_symbol_cache(id.pid, addr, sym.name);
                    }
                    else
                    {
                        std::stringstream ss("");
                        ss << "0x" << std::hex << sym.ip;
                        sym.name = ss.str();
                        g_symbol_parser.putin_symbol_cache(id.pid, addr, sym.name);
                    }
                    sym_trace[i++] = sym.name;
                }
                traces[id.usid] = sym_trace;
            }
            if (id.ksid > 0 && traces.find(id.ksid) == traces.end())
            {
                bpf_map_lookup_elem(trace_fd, &id.ksid, trace);
                for (p = trace + MAX_STACKS - 1; !*p; p--)
                    ;
                std::vector<std::string> sym_trace(p - trace + 1);
                for (int i = 0; p >= trace; p--)
                {
                    uint64_t &addr = *p;
                    symbol sym;
                    sym.reset(addr);
                    std::stringstream ss("");
                    if (g_symbol_parser.find_kernel_symbol(sym))
                    {
                        ss << "+0x" << std::hex << (sym.ip - sym.start);
                        sym.name += ss.str();
                        clearSpace(sym.name);
                    }
                    else
                    {
                        ss << "0x" << std::hex << addr;
                        sym.name = ss.str();
                    }
                    sym_trace[i++] = sym.name;
                }
                traces[id.ksid] = sym_trace;
            }
            auto info_fd = bpf_object__find_map_fd_by_name(obj, "pid_info_map");
            task_info info;
            bpf_map_lookup_elem(info_fd, &id.pid, &info);
            infos[id.pid] = info;
        }
        delete D;
    }

    oss << _BLUE "traces:" _RE "\n";
    {
        oss << _GREEN "sid\ttrace" _RE "\n";
        for (auto i : traces)
        {
            oss << i.first << "\t";
            for (auto s : i.second)
                oss << s << ';';
            oss << "\n";
        }
    }

    oss << _BLUE "info:" _RE "\n";
    {
        oss << _GREEN "pid\tNSpid\tcomm\ttgid\tcgroup\t" _RE "\n";
        for (auto i : infos)
        {
            auto cgroup_fd = bpf_object__find_map_fd_by_name(obj, "tgid_cgroup_map");
            char group[CONTAINER_ID_LEN];
            bpf_map_lookup_elem(cgroup_fd, &(i.second.tgid), &group);
            oss << i.first << '\t'
                << i.second.pid << '\t'
                << i.second.comm << '\t'
                << i.second.tgid << '\t'
                << group << '\n';
        }
    }

    oss << _BLUE "OK" _RE "\n";
    return oss.str();
}
