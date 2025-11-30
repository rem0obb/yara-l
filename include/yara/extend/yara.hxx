#pragma once

#include <interfaces/ilua.hxx>
#include <lua/lua.hxx>

namespace yara::extend
{
  class Yara : public interface::ILua<Yara>
  {
  public:
    Yara(lua::Lua &);
    ~Yara() = default;

    void _bind() override;

  private:
    lua::Lua &lua_;
    inline void bind_flags();
    inline void bind_import();
    inline void bind_string();
    inline void bind_namespace();
    inline void bind_meta();
    inline void bind_rule();
    inline void bind_stream();
    inline void bind_yara();
  };
} // namespace yara::extend
