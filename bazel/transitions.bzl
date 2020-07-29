#
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
This file defines a version of the Starlark-native `cc_binary` rule that
supports an additional, optional `global_copts` attribute.

`global_copts` is a list of strings representing compiler options to pass to
the C++ compilation command. `global_copts` behaves similarly to the built-in
`copts` attribute: each string in this attribute is added in the given order to
`COPTS` before compiling the binary target. However, unlike `copts`, options
passed in `global_copts` are propogated to the target's dependencies as well.
"""

# Implementation of `_copt_transition`.
def _copt_transition_impl(settings, attr):
    # `settings` provides read-only access to existing flags on the build.
    # However, this transition won't read any flags (since the `inputs`
    # attribute of `_copt_transition` is empty), so we can ignore it here.
    _ignore = settings

    # This adds all of the options specified in the owning rule's `global_copts`
    # attribute as a compilation flag.
    return {"//command_line_option:copt": attr.global_copts}

# `_copt_transition` defines a Starlark transition that universally sets
# `//command_line_option:copt` to the list of options that are specified in the
# owning rule's `global_copts` attribute.
#
# `inputs` is purposely empty as this transition does not need to read any
# existing flags (it's only adding new ones).
_copt_transition = transition(
    implementation = _copt_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:copt"],
)

# Implementation of `transition_rule`. This copies the `cc_binary`'s output to
# `transition_rule`'s own output, then propogates its runfiles and executable
# back to Bazel. This makes `transition_rule` as close to a pure wrapper of
# `cc_binary` as possible.
def _transition_rule_impl(ctx):
    actual_binary = ctx.attr.actual_binary[0]
    outfile = ctx.actions.declare_file(ctx.label.name)
    cc_binary_outfile = actual_binary[DefaultInfo].files.to_list()[0]

    ctx.actions.run_shell(
        inputs = [cc_binary_outfile],
        outputs = [outfile],
        command = "cp %s %s" % (cc_binary_outfile.path, outfile.path),
    )
    return [
        DefaultInfo(
            executable = outfile,
            data_runfiles = actual_binary[DefaultInfo].data_runfiles,
        ),
    ]

# `transition_rule` consumes a `global_copts` attribute and invokes a
# transition that sets `//command_line_option:copt` to the specified list of
# strings in `global_copts`.
#
# While `transition_rule` could directly be included in a BUILD file, we
# define a `cc_binary` macro for convenience so the BUILD file can look as close
# to normal as possible.
transition_rule = rule(
    implementation = _transition_rule_impl,
    attrs = {
        # This is where the user can set the feature they want.
        "global_copts": attr.string_list(default = []),
        # This is the cc_binary whose deps will select() on that feature.
        # Note specificaly how it's configured with _copt_transition, which
        # ensures that our `global_copts` propogate down the build graph.
        "actual_binary": attr.label(cfg = _copt_transition),
        # This is a stock Bazel requirement for any rule that uses Starlark
        # transitions. The purpose of this requirement is to give the ability to
        # restrict which packages can invoke these rules, since Starlark
        # transitions make much larger graphs possible that can have memory and
        # performance consequences for the build. The whitelist currently
        # defaults to "everything".
        "_whitelist_function_transition": attr.label(
            default = "@bazel_tools//tools/whitelists/function_transition_whitelist",
        ),
    },
    # Making this executable means it works with "$ bazel run".
    executable = True,
)

# Convenience macro: this instantiates a `transition_rule` with the given
# desired `global_copts`, instantiates a `cc_binary` as a dependency of that
# rule, and fills out that `cc_binary` rule with all other parameters passed to
# this macro.
#
# The result is a wrapper over cc_binary that "magically" gives it a new
# `global_copts` attribute. BUILD users who wish to use this version of
# `cc_binary` need to `load(...)` this version at the top of their BUILD file.
def cc_binary(name, global_copts = None, **kwargs):
    cc_binary_name = name + "_native_binary"
    transition_rule(
        name = name,
        actual_binary = ":%s" % cc_binary_name,
        global_copts = global_copts,
    )
    native.cc_binary(
        name = cc_binary_name,
        **kwargs
    )
