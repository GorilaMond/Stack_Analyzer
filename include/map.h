#include <bpf/libbpf.h>

bool pin_map(bpf_object *obj, std::string map_name, std::string dir_path)
{
    struct bpf_map *bpf_map = bpf_object__find_map_by_name(obj, map_name.c_str());
    if (!bpf_map)
    {
        fprintf(stderr, "Failed to find BPF map\n");
        return false;
    }
    auto map_path = dir_path + '/' + map_name;
    bpf_map__unpin(bpf_map, map_path.c_str());
    if (bpf_map__pin(bpf_map, map_path.c_str()))
    {
        fprintf(stderr, "Failed to pin BPF map\n");
        return false;
    }
    return true;
}