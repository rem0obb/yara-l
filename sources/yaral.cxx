#include <lua/lua.hxx>
#include <yara/extend/yara.hxx>

extern "C" int luaopen_yaral(lua_State* L)
{
    auto lua = lua::Lua(L);

    auto yara = yara::extend::Yara(lua);
    yara._bind(); 

    lua.state["version"] = "0.0.1";

    return 0;
}
