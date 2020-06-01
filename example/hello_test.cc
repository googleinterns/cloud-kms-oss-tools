#include "example/hello.h"
#include "gtest/gtest.h"

namespace hello {
namespace {

TEST(Hello, CorrectName) {
    Hello hello("Foo");
    EXPECT_EQ(hello.hello_string(), "Hello, Foo!");
}

}  // namespace
}  // namespace hello