#include <string>
#include "absl/strings/string_view.h"

namespace hello {

class Hello
{
public:
    Hello(absl::string_view name);

    std::string hello_string() { return hello_string_; }

private:
    std::string hello_string_;
};

}  // namespace