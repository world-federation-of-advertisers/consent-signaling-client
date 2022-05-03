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
#        sha256 = "271abea7a8b940ef582f4d835a868bf4a603f1080916a2ce9f6c8909a44dcba8",
        strip_prefix = "common-jvm-42eb74272d31c5c16428023d1f8763fb690e5f25",
        url = "https://github.com/world-federation-of-advertisers/common-jvm/archive/42eb74272d31c5c16428023d1f8763fb690e5f25.tar.gz",
    )

    http_archive(
        name = "wfa_measurement_proto",
#        sha256 = "611bbc8c653868c1dbc973a520a192d8ac1678375167181354fc9b1bc8e3a3ea",
        strip_prefix = "cross-media-measurement-api-0.22.1",
        url = "https://github.com/world-federation-of-advertisers/cross-media-measurement-api/archive/refs/tags/v0.22.1.tar.gz",
    )