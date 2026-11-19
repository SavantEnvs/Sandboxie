// SimpleJSON parser (Sandboxie/common/json) as used by UpdUtil on update.json
// and add-on manifests: parse, re-serialize, walk.
#include <stdint.h>
#include <stddef.h>
#include <string>
#include "common/json/JSON.h"

static void walk(JSONValue *v, int depth)
{
    if (!v || depth > 64) return;
    if (v->IsObject()) {
        std::vector<std::wstring> keys = v->ObjectKeys();
        for (size_t i = 0; i < keys.size(); i++) {
            if (v->HasChild(keys[i].c_str()))
                walk(v->Child(keys[i].c_str()), depth + 1);
        }
    } else if (v->IsArray()) {
        for (size_t i = 0; i < v->CountChildren(); i++)
            walk(v->Child(i), depth + 1);
    } else if (v->IsString()) {
        (void)v->AsString().size();
    } else if (v->IsNumber()) {
        (void)v->AsNumber();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::wstring ws;
    ws.reserve(size);
    for (size_t i = 0; i < size && data[i]; i++) ws.push_back((wchar_t)data[i]);
    JSONValue *v = JSON::Parse(ws.c_str());
    if (!v) return 0;
    std::wstring out = JSON::Stringify(v);
    walk(v, 0);
    (void)v->Stringify(true);
    delete v;
    // Serializer output must itself parse.
    JSONValue *v2 = JSON::Parse(out.c_str());
    delete v2;
    return 0;
}
