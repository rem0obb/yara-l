#pragma once

extern "C"
{
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}
#include <lua/entitys.hxx>
#include <functional>
#include <memory>
#include <sol/sol.hpp>
#include <string>

namespace lua
{
  class Lua
  {
  public:
    Lua(lua_State* L);
    ~Lua() = default;
    StateView state;

  private:
    Lua(const Lua &) = delete;
    Lua &operator=(const Lua &) = delete;
  };

} // namespace lua