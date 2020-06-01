#include "example/hello.h"

#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"

namespace hello
{

    Hello::Hello(absl::string_view name) : hello_string_(absl::Substitute("Hello, $0!", name)) {}

} // namespace hello