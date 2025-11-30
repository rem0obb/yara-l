#include <lua/exception.hxx>

namespace lua
{
    namespace exception
    {
        Runtime::Runtime(const std::string &p_message) : error_message_(p_message)
        {
        }

        const char *Runtime::what() const noexcept
        {
            return error_message_.c_str();
        }
    } // namespace exception
} // namespace lua
