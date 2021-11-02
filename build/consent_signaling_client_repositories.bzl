# Copyright 2021 The Cross-Media Measurement Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Adds external repos necessary for consent-signaling-client.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def consent_signaling_client_repositories():
    """
    Adds all external repos necessary for consent-signaling-client.
    """
    http_archive(
        name = "wfa_common_jvm",
        sha256 = "12819b095363d8294bd01c0e9c2cf847b21f895e96923b8a8c07836c8cd2c042",
        strip_prefix = "common-jvm-0.20.1",
        url = "https://github.com/world-federation-of-advertisers/common-jvm/archive/refs/tags/v0.20.1.tar.gz",
    )

    http_archive(
        name = "wfa_measurement_proto",
        sha256 = "4385a6ae12684d8896affdd60c19a470b284623b5094685dd3a616fd30178c52",
        strip_prefix = "cross-media-measurement-api-0.9.0",
        url = "https://github.com/world-federation-of-advertisers/cross-media-measurement-api/archive/refs/tags/v0.9.0.tar.gz",
    )
