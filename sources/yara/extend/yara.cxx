#include <lua/lua.hxx>
#include <lua/exception.hxx>
#include <yara/extend/yara.hxx>
#include <fmt/core.h>
#include <memory>
#include <yara/yara.hxx>

namespace yara::extend
{
    Yara::Yara(lua::Lua &lua) : lua_(lua) 
    {

    }

    void Yara::bind_import()
    {
        lua_.state.new_usertype<YR_MODULE_IMPORT>(
            "Import",
            "new",
            sol::constructors<YR_MODULE_IMPORT()>(),
            "module_name",
            sol::readonly(&YR_MODULE_IMPORT::module_name));
    }

    void Yara::bind_flags()
    {
        lua_.state.new_enum<yara::type::Flags>(
            "YaraFlags",
            {// Callback message types
             {"RuleMatching", yara::type::Flags::RuleMatching},
             {"RuleNotMatching", yara::type::Flags::RuleNotMatching},
             {"ScanFinished", yara::type::Flags::ScanFinished},
             {"ImportModule", yara::type::Flags::ImportModule},
             {"ModuleImported", yara::type::Flags::ModuleImported},
             {"TooManyMatches", yara::type::Flags::TooManyMatches},
             {"ConsoleLog", yara::type::Flags::ConsoleLog},
             {"TooSlowScanning", yara::type::Flags::TooSlowScanning},

             // Callback return codes
             {"ContinueScan", yara::type::Flags::ContinueScan},
             {"AbortScan", yara::type::Flags::AbortScan},
             {"ErrorScan", yara::type::Flags::ErrorScan},

             // Scan flags
             {"FastMode", yara::type::Flags::FastMode},
             {"ProcessMemory", yara::type::Flags::ProcessMemory},
             {"NoTryCatch", yara::type::Flags::NoTryCatch},
             {"ReportRulesMatching", yara::type::Flags::ReportRulesMatching},
             {"ReportRulesNotMatching",
              yara::type::Flags::ReportRulesNotMatching}});
    }

    void Yara::bind_match()
    {
        lua_.state.new_usertype<YR_MATCH>(
            "Match",
            "new",
            sol::constructors<YR_MATCH()>(),
            "base",
            sol::readonly(&YR_MATCH::base),
            "offset",
            sol::readonly(&YR_MATCH::offset),
            "match_length",
            sol::readonly(&YR_MATCH::match_length),
            "data_length",
            sol::readonly(&YR_MATCH::data_length),
            "data",
            sol::property([](const YR_MATCH &m)
                          { return std::string(reinterpret_cast<const char *>(m.data),
                                               m.data_length); }));
    }

    void Yara::bind_string()
    {
        lua_.state.new_usertype<YR_STRING>(
            "String",
            "new",
            sol::constructors<YR_STRING()>(),
            "flags",
            sol::readonly(&YR_STRING::flags),
            "idx",
            sol::readonly(&YR_STRING::idx),
            "fixed_offset",
            sol::readonly(&YR_STRING::fixed_offset),
            "rule_idx",
            sol::readonly(&YR_STRING::rule_idx),
            "length",
            sol::readonly(&YR_STRING::length),
            "string",
            sol::property([](const YR_STRING &s)
                          { return std::string(reinterpret_cast<const char *>(s.string),
                                               s.length); }),
            "identifier",
            sol::readonly(&YR_STRING::identifier));
    }

    void Yara::bind_namespace()
    {
        lua_.state.new_usertype<YR_NAMESPACE>(
            "Namespace",
            "new",
            sol::constructors<YR_NAMESPACE()>(),
            "name",
            sol::readonly(&YR_NAMESPACE::name),
            "idx",
            sol::readonly(&YR_NAMESPACE::idx));
    }

    void Yara::bind_meta()
    {
        lua_.state.new_usertype<YR_META>(
            "Meta",
            "new",
            sol::constructors<YR_META()>(),
            "flags",
            sol::readonly(&YR_META::flags),
            "type",
            sol::readonly(&YR_META::type),
            "identifier",
            sol::readonly(&YR_META::identifier),
            "integer",
            sol::readonly(&YR_META::integer),
            "string",
            sol::readonly(&YR_META::string));
    }

    void Yara::bind_rule()
    {
        lua_.state.new_usertype<YR_RULE>(
            "Rule",
            "new",
            sol::constructors<YR_RULE()>(),
            "flags",
            sol::readonly(&YR_RULE::flags),
            "num_atoms",
            sol::readonly(&YR_RULE::num_atoms),
            "required_strings",
            sol::readonly(&YR_RULE::required_strings),
            "identifier",
            sol::readonly(&YR_RULE::identifier),
            "tags",
            sol::readonly(&YR_RULE::tags),
            "ns",
            sol::readonly(&YR_RULE::ns),
            "strings",
            sol::readonly(&YR_RULE::strings),
            "metas",
            sol::readonly(&YR_RULE::metas));
    }

    void Yara::bind_stream()
    {
        lua_.state.new_usertype<YR_STREAM>(
            "Stream",
            "new",
            sol::constructors<YR_STREAM()>(),
            "read",
            [](YR_STREAM &stream, sol::function func)
            {
                auto func_ptr =
                    std::make_shared<sol::function>(std::move(func));

                stream.user_data = static_cast<void *>(
                    new std::shared_ptr<sol::function>(func_ptr));

                stream.read = [](void *ptr,
                                 size_t size,
                                 size_t count,
                                 void *user_data) -> size_t
                {
                    if (!user_data)
                    {
                        throw lua::exception::Runtime(
                            "Callback not valid (null user_data)");
                    }

                    auto *func_shared_ptr =
                        static_cast<std::shared_ptr<sol::function> *>(
                            user_data);
                    sol::function &lua_read_func = **func_shared_ptr;

                    const size_t total_size = size * count;

                    sol::protected_function_result result =
                        lua_read_func(total_size);
                    if (!result.valid())
                    {
                        sol::error err = result;
                        throw lua::exception::Runtime(
                            fmt::format("Lua callback error: {}", err.what()));
                    }

                    const std::string data = result.get<std::string>();
                    size_t bytes_read = std::min(total_size, data.size());

                    std::memcpy(ptr, data.data(), bytes_read);

                    return bytes_read / size;
                };
            },
            "write",
            [](YR_STREAM &stream, sol::function func)
            {
                auto func_ptr =
                    std::make_shared<sol::function>(std::move(func));

                stream.user_data = static_cast<void *>(
                    new std::shared_ptr<sol::function>(func_ptr));

                stream.write = [](const void *ptr,
                                  size_t size,
                                  size_t count,
                                  void *user_data) -> size_t
                {
                    if (!user_data)
                    {
                        throw lua::exception::Runtime(
                            "Callback not valid (null user_data)");
                    }

                    auto *func_shared_ptr =
                        static_cast<std::shared_ptr<sol::function> *>(
                            user_data);
                    sol::function &lua_write_func = **func_shared_ptr;

                    const size_t total_size = size * count;
                    std::string data(static_cast<const char *>(ptr),
                                     total_size);

                    sol::protected_function_result result =
                        lua_write_func(data);
                    if (!result.valid())
                    {
                        sol::error err = result;
                        throw lua::exception::Runtime(
                            fmt::format("Lua callback error: {}", err.what()));
                    }

                    return count;
                };
            });
    }

    void Yara::bind_yara()
    {
        lua_.state.new_usertype<yara::Yara>(
            "Yara",
            "new",
            sol::constructors<yara::Yara()>(),
            "rule_disable",
            &yara::Yara::rule_disable,
            "rule_enable",
            &yara::Yara::rule_enable,
            "unload_rules",
            &yara::Yara::unload_rules,
            "load_rules_stream",
            &yara::Yara::load_rules_stream,
            "rules_foreach",
            &yara::Yara::rules_foreach,
            "metas_foreach",
            &yara::Yara::metas_foreach,
            "tags_foreach",
            &yara::Yara::tags_foreach,
            "strings_foreach",
            &yara::Yara::strings_foreach,
            "save_rules_stream",
            &yara::Yara::save_rules_stream,
            "load_compiler",
            &yara::Yara::load_compiler,
            "unload_compiler",
            &yara::Yara::unload_compiler,
            "set_rules_folder",
            &yara::Yara::set_rules_folder,
            "load_rules",
            &yara::Yara::load_rules,
            "scan_bytes",
            [](yara::Yara &self,
               const std::string &buffer,
               sol::function func,
               yara::type::Flags flags)
            {
                if (!func.valid())
                {
                    return;
                }
                struct LuaScanData
                {
                    sol::function *func;
                    std::exception_ptr pending;
                };
                LuaScanData cbData{&func, nullptr};
                self.scan_bytes(
                    buffer,
                    +[](YR_SCAN_CONTEXT *context,
                        int message,
                        void *message_data,
                        void *user_data) -> int
                    {
                        auto *d = static_cast<LuaScanData *>(user_data);
                        if (!d->func || !d->func->valid())
                            return CALLBACK_CONTINUE;
                        try
                        {
                            sol::protected_function_result result;
                            switch (message)
                            {
                            case CALLBACK_MSG_RULE_NOT_MATCHING:
                            case CALLBACK_MSG_RULE_MATCHING:
                            {
                                const YR_RULE *rule =
                                    reinterpret_cast<YR_RULE *>(message_data);
                                result = (*d->func)(message, rule);
                                break;
                            }
                            case CALLBACK_MSG_SCAN_FINISHED:
                                result = (*d->func)(message, sol::lua_nil);
                                break;
                            case CALLBACK_MSG_TOO_MANY_MATCHES:
                            {
                                const YR_STRING *string =
                                    reinterpret_cast<YR_STRING *>(message_data);
                                result = (*d->func)(message, string);
                                break;
                            }
                            case CALLBACK_MSG_CONSOLE_LOG:
                            {
                                const char *log =
                                    reinterpret_cast<const char *>(message_data);
                                result = (*d->func)(message, log);
                                break;
                            }
                            case CALLBACK_MSG_IMPORT_MODULE:
                            {
                                const YR_MODULE_IMPORT *module_import =
                                    reinterpret_cast<YR_MODULE_IMPORT *>(
                                        message_data);
                                result = (*d->func)(message, module_import);
                                break;
                            }
                            default:
                                result = (*d->func)(message);
                                break;
                            }
                            if (!result.valid())
                            {
                                sol::error err = result;
                                throw lua::exception::Runtime(fmt::format(
                                    "Lua callback error in scan_bytes: {}",
                                    err.what()));
                            }
                            return static_cast<int>(result);
                        }
                        catch (...)
                        {
                            d->pending = std::current_exception();
                            return CALLBACK_ABORT;
                        }
                    },
                    static_cast<void *>(&cbData),
                    flags);
                if (cbData.pending)
                    std::rethrow_exception(cbData.pending);
            },
            "load_rules_file",
            &yara::Yara::load_rules_file,
            "set_rule_buff",
            &yara::Yara::set_rule_buff,
            "set_rule_file",
            &yara::Yara::set_rule_file,
            "save_rules_file",
            &yara::Yara::save_rules_file,
            "scan_file",
            [](yara::Yara &self,
               const std::string &path,
               sol::function func,
               yara::type::Flags flags)
            {
                if (!func.valid())
                {
                    return;
                }
                struct LuaScanData
                {
                    sol::function *func;
                    std::exception_ptr pending;
                };
                LuaScanData cbData{&func, nullptr};
                self.scan_file(
                    path,
                    +[](YR_SCAN_CONTEXT *context,
                        int message,
                        void *message_data,
                        void *user_data) -> int
                    {
                        auto *d = static_cast<LuaScanData *>(user_data);
                        if (!d->func || !d->func->valid())
                            return CALLBACK_CONTINUE;
                        try
                        {
                            sol::protected_function_result result;
                            switch (message)
                            {
                            case CALLBACK_MSG_RULE_NOT_MATCHING:
                            case CALLBACK_MSG_RULE_MATCHING:
                            {
                                const YR_RULE *rule =
                                    reinterpret_cast<YR_RULE *>(message_data);
                                result = (*d->func)(message, rule);
                                break;
                            }
                            case CALLBACK_MSG_SCAN_FINISHED:
                                result = (*d->func)(message, sol::lua_nil);
                                break;
                            case CALLBACK_MSG_TOO_MANY_MATCHES:
                            {
                                const YR_STRING *string =
                                    reinterpret_cast<YR_STRING *>(message_data);
                                result = (*d->func)(message, string);
                                break;
                            }
                            case CALLBACK_MSG_CONSOLE_LOG:
                            {
                                const char *log =
                                    reinterpret_cast<const char *>(message_data);
                                result = (*d->func)(message, log);
                                break;
                            }
                            case CALLBACK_MSG_IMPORT_MODULE:
                            {
                                const YR_MODULE_IMPORT *module_import =
                                    reinterpret_cast<YR_MODULE_IMPORT *>(
                                        message_data);
                                result = (*d->func)(message, module_import);
                                break;
                            }
                            default:
                                result = (*d->func)(message);
                                break;
                            }
                            if (!result.valid())
                            {
                                sol::error err = result;
                                throw lua::exception::Runtime(fmt::format(
                                    "Lua callback error in scan_file: {}",
                                    err.what()));
                            }
                            return static_cast<int>(result);
                        }
                        catch (...)
                        {
                            d->pending = std::current_exception();
                            return CALLBACK_ABORT;
                        }
                    },
                    static_cast<void *>(&cbData),
                    flags);
                if (cbData.pending)
                    std::rethrow_exception(cbData.pending);
            },
            "matches_foreach",
            [](yara::Yara &self,
               YR_SCAN_CONTEXT *context,
               YR_STRING *string,
               sol::function func)
            {
                if (!func.valid())
                {
                    return;
                }
                self.matches_foreach(
                    context,
                    string,
                    [&func](const YR_MATCH &match)
                    {
                        sol::protected_function_result result =
                            func(&match);
                        if (!result.valid())
                        {
                            sol::error err = result;
                            throw lua::exception::Runtime(fmt::format(
                                "Lua callback error in matches_foreach: {}\n",
                                err.what()));
                        }
                    });
            },
            "define_integer_variable",
            &yara::Yara::define_integer_variable,
            "define_boolean_variable",
            &yara::Yara::define_boolean_variable,
            "define_string_variable",
            &yara::Yara::define_string_variable,
            "define_float_variable",
            &yara::Yara::define_float_variable,
            "set_compiler_callback",
            [](yara::Yara &self, sol::function func)
            {
                if (!func.valid())
                {
                    return;
                }
                auto func_ptr =
                    std::make_shared<sol::function>(std::move(func));
                self.set_compiler_callback(
                    +[](int error_level,
                        const char *file_name,
                        int line_number,
                        const YR_RULE *rule,
                        const char *message,
                        void *user_data)
                    {
                        auto *fp =
                            static_cast<std::shared_ptr<sol::function> *>(
                                user_data);
                        if (!fp || !(*fp)->valid())
                            return;
                        try
                        {
                            (**fp)(error_level,
                                   file_name ? std::string(file_name)
                                             : std::string(),
                                   line_number,
                                   message ? std::string(message)
                                           : std::string());
                        }
                        catch (...)
                        {
                            // Never let exceptions escape through YARA's C code
                        }
                    },
                    static_cast<void *>(
                        new std::shared_ptr<sol::function>(func_ptr)),
                    [](void *user_data)
                    {
                        delete static_cast<std::shared_ptr<sol::function> *>(
                            user_data);
                    });
            });
    }

    void Yara::_bind()
    {
        Yara::bind_import();
        Yara::bind_match();
        Yara::bind_string();
        Yara::bind_namespace();
        Yara::bind_meta();
        Yara::bind_rule();
        Yara::bind_stream();
        Yara::bind_yara();
        Yara::bind_flags();
    }
} // namespace yara::Yara::extend
