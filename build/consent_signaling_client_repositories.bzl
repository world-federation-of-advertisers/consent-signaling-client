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
        sha256 = "6a88080cd751566c2f97b31dbc7ef5e8e1016957c87866e25229e01c48d71ab4",
        strip_prefix = "common-jvm-0.49.0",
        url = "https://github.com/world-federation-of-advertisers/common-jvm/archive/refs/tags/v0.49.0.tar.gz",
    )

    http_archive(
        name = "wfa_measurement_proto",
        sha256 = "8412e478f15119b624e6696b578ca308b55f61a240e83ea2f72444692118d1ff",
        strip_prefix = "cross-media-measurement-api-0.24.0",
        url = "https://github.com/world-federation-of-advertisers/cross-media-measurement-api/archive/refs/tags/v0.24.0.tar.gz",
    )
