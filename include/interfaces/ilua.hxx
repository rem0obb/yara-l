#pragma once

namespace interface
{
    template <typename Derived> class ILua
    {
      public:
        virtual ~ILua() = default;
        static inline void plugins()
        {
            Derived()._bind();
        }

      private:
        virtual void _bind() = 0;
    };
} // namespace engine::interface
