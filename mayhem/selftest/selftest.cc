// Known-answer test driver: SimpleJSON checks here, C parser checks in selftest_c.c.
#include <cstdio>
#include <string>
#include "common/json/JSON.h"
#include <windows.h>
#include "helpers.h"

extern "C" void c_checks(void (*report)(const char *, int));

static int passed, failed;
static void report(const char *name, int ok)
{
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) passed++; else failed++;
}

int main()
{
    JSONValue *v = JSON::Parse(L"{\"a\": [1, 2.5, \"x\\u0041\"], \"b\": true, \"c\": null}");
    report("json_parse_object", v && v->IsObject());
    if (v && v->IsObject()) {
        JSONValue *a = v->Child(L"a");
        report("json_array", a && a->IsArray() && a->CountChildren() == 3);
        report("json_number", a && a->Child((size_t)1)->IsNumber() && a->Child((size_t)1)->AsNumber() == 2.5);
        report("json_string_escape", a && a->Child((size_t)2)->IsString() && a->Child((size_t)2)->AsString() == L"xA");
        report("json_bool", v->Child(L"b") && v->Child(L"b")->IsBool() && v->Child(L"b")->AsBool());
        report("json_null", v->Child(L"c") && v->Child(L"c")->IsNull());
        std::wstring s = JSON::Stringify(v);
        JSONValue *v2 = JSON::Parse(s.c_str());
        report("json_roundtrip", v2 && JSON::Stringify(v2) == s && s.find(L"\"a\"") != std::wstring::npos);
        delete v2;
    }
    delete v;
    report("json_reject_garbage", JSON::Parse(L"{\"a\": }") == NULL);
    {
        std::wstring first;
        auto a = GetArguments(L"upd.exe /mode=check name='a b' x=\"q\\\"r\"", L' ', L'=', &first, true, true);
        report("getargs_first", first == L"upd.exe");
        report("getargs_value", a.count(L"/mode") == 1 && a.find(L"/mode")->second == L"check");
        report("getargs_quoted", a.count(L"name") == 1 && a.find(L"name")->second == L"a b");
        report("getargs_escape", a.count(L"x") == 1 && a.find(L"x")->second == L"q\"r");
        auto c = GetArguments(L"NAME: John\nTYPE: CONTRIBUTOR\n", L'\n', L':');
        report("getargs_cert", c.count(L"TYPE") == 1 && c.find(L"TYPE")->second == L"CONTRIBUTOR");
        report("wildstrcmp", wildstrcmp(L"*.exe", L"setup.exe") != NULL && wildstrcmp(L"*.exe", L"setup.dll") == NULL);
    }
    c_checks(report);
    std::printf("SUMMARY passed=%d failed=%d\n", passed, failed);
    return failed ? 1 : 0;
}
