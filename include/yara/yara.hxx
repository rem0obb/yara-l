#pragma once

#include <atomic>
#include <yara/entitys.hxx>
#include <yara/extend/yara.hxx>
#include <filesystem>
#include <functional>
#include <shared_mutex>
#include <stack>
#include <string>
#include <yara.h>

namespace yara
{
    class Yara; // Forward declaration yara plugin

    class Yara
    {
    public:
        Yara();
        ~Yara();

        friend class yara::extend::Yara;

        /**
         * @brief function for scan, but, you pass flag and callback for
         * scan yara YR_CALLBACK_FUNC
         * @param YR_CALLBACK_FUNC callback for scan yara
         * @param void* user_data, pass for example Yr::Structs::Data
         * @param int flags used for scan
         */
        void scan_bytes(const std::string &,
                        YR_CALLBACK_FUNC,
                        void *,
                        yara::type::Flags) const;

        void scan_file(const std::string &,
                       YR_CALLBACK_FUNC,
                       void *,
                       yara::type::Flags) const;

        void rule_disable(YR_RULE &);
        void rule_enable(YR_RULE &);
        void rules_foreach(const std::function<void(const YR_RULE &)> &);

        void metas_foreach(YR_RULE *,
                           const std::function<void(const YR_META &)> &);

        void strings_foreach(
            YR_RULE *, const std::function<void(const YR_STRING &)> &);

        void tags_foreach(YR_RULE *,
                          const std::function<void(const char *)> &);

        void matches_foreach(YR_SCAN_CONTEXT *,
                             YR_STRING *,
                             const std::function<void(const YR_MATCH &)> &);

        const int load_rules_file(const char *);
        const int save_rules_file(const char *);

        void unload_rules();
        [[nodiscard]] const int load_rules_stream(YR_STREAM &);
        [[nodiscard]] const int save_rules_stream(YR_STREAM &);
        [[nodiscard]] const int load_compiler();
        void unload_compiler();

        void load_rules() const;

        /* load rules if extension file '.yar'*/
        void set_rules_folder(const std::string & /* path */) const;

        [[nodiscard]] const int set_rule_buff(const std::string &,
                                              const std::string &) const;
        [[nodiscard]] const int set_rule_file(const std::string &,
                                              const std::string &,
                                              const std::string &) const;

        void define_integer_variable(const std::string &, int64_t) const;
        void define_boolean_variable(const std::string &, bool) const;
        void define_string_variable(const std::string &,
                                    const std::string &) const;
        void define_float_variable(const std::string &, double) const;

        void set_compiler_callback(YR_COMPILER_CALLBACK_FUNC,
                                   void *,
                                   std::function<void(void *)> = {});

    private:
        static std::mutex lifecycle_mutex_;
        static size_t lifecycle_refs_;

        mutable std::mutex compiler_mutex_;
        mutable std::shared_mutex rules_mutex_;

        template <typename Callback>
        void execute_safely(Callback &&cb) const
        {
            const std::shared_lock<std::shared_mutex> lock(rules_mutex_);
            cb();
        }

        YR_COMPILER *yara_compiler_;
        mutable YR_RULES *yara_rules_;
        void *compiler_callback_user_data_;
        std::function<void(void *)> compiler_callback_cleanup_;

        void clear_compiler_callback_locked();
        void compiler_rules() const;
    };
} // namespace security
