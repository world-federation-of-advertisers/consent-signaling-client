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
        sha256 = "5c6e7fed4295aeda87bbe8b9bc85a2c0ab4190fc71a6596a7babd6880b730bec",
        strip_prefix = "common-jvm-0.59.0",
        url = "https://github.com/world-federation-of-advertisers/common-jvm/archive/refs/tags/v0.59.0.tar.gz",
    )

    http_archive(
        name = "wfa_measurement_proto",
        sha256 = "8cb0e25bb0bcc2dae6d175613b6b8b827f6a48e15592399c9a5534a7b18b4d07",
        strip_prefix = "cross-media-measurement-api-0.36.0",
        url = "https://github.com/world-federation-of-advertisers/cross-media-measurement-api/archive/refs/tags/v0.36.0.tar.gz",
    )
