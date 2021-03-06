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
        sha256 = "9505024528afc9e7a9e126a297458fa4503a33ff21c55bac58e5184385f492e2",
        strip_prefix = "common-jvm-0.35.0",
        url = "https://github.com/world-federation-of-advertisers/common-jvm/archive/v0.35.0.tar.gz",
    )

    http_archive(
        name = "wfa_measurement_proto",
        sha256 = "da28ccac88a12b3b75b974b92604b8e332b8bc91cd276afab1ee41415fa320a3",
        strip_prefix = "cross-media-measurement-api-0.22.2",
        url = "https://github.com/world-federation-of-advertisers/cross-media-measurement-api/archive/refs/tags/v0.22.2.tar.gz",
    )
