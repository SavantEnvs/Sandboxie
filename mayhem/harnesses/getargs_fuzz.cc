// Argument-string parser GetArguments (SandboxieTools/Common/helpers.cpp),
// used on the UpdUtil and ImBox command lines, plus the wildstrcmp/SplitStr helpers
// from helpers.h. Input byte 0 picks separators/flags, the rest is the string.
#include <stdint.h>
#include <stddef.h>
#include <windows.h>
#include "helpers.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return -1;
    static const wchar_t seps[][2] = { { L' ', L'=' }, { L';', L'=' }, { L',', L':' }, { L'\n', L':' } }; // last: Certificate.dat (UpdUtil.cpp)
    uint8_t mode = data[0];
    std::wstring s;
    for (size_t i = 1; i < size; i++) s.push_back((wchar_t)data[i]);
    std::wstring first;
    const wchar_t *sp = seps[mode & 3];
    std::multimap<std::wstring, std::wstring> args =
        GetArguments(s, sp[0], sp[1], (mode & 4) ? &first : NULL, (mode & 8) != 0, (mode & 16) != 0);
    for (auto &kv : args) {
        if (!kv.first.empty())
            (void)wildstrcmp(kv.first.c_str(), kv.second.c_str());
        (void)SplitStr(kv.second, L",", (mode & 32) != 0, (mode & 64) != 0);
    }
    return 0;
}
