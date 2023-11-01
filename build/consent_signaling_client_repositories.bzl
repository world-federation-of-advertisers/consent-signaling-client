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
        sha256 = "d786cf15e4d97a0b862a75fecde6225507530fbba4bb702a3167f8316b4c89c7",
        strip_prefix = "common-jvm-0.68.0",
        url = "https://github.com/world-federation-of-advertisers/common-jvm/archive/refs/tags/v0.68.0.tar.gz",
    )

    http_archive(
        name = "wfa_measurement_proto",
        sha256 = "929cfe5953b139a61f24b264a75a8c830ed010e4f661d5703eef57bd6c24e6aa",
        strip_prefix = "cross-media-measurement-api-0.48.0",
        url = "https://github.com/world-federation-of-advertisers/cross-media-measurement-api/archive/refs/tags/v0.48.0.tar.gz",
    )
