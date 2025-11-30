#pragma once

#include <interfaces/iexception.hxx>

namespace lua
{
  namespace exception
  {
    class Runtime : public interface::IException
    {
    private:
      const std::string error_message_;

    public:
      explicit Runtime(const std::string &);
      const char *what() const noexcept override;
    };
  } // namespace exception
} // namespace lua
