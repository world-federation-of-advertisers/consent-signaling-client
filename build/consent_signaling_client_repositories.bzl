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
        sha256 = "265c274fd5a618dcb8bced9f1c881bc1e3a2e973e6b269a887544b3ab3162a4a",
        # TODO(world-federation-of-advertisers/common-jvm#216): Use version.
        strip_prefix = "common-jvm-3a59e8f2502b96f200436c885beda84c9bdad6b0",
        url = "https://github.com/world-federation-of-advertisers/common-jvm/archive/3a59e8f2502b96f200436c885beda84c9bdad6b0.tar.gz",
    )

    http_archive(
        name = "wfa_measurement_proto",
        sha256 = "b6ee5ff56c8c8ec8f6f44c93fe273d4120779dcd0954e9d69929137da2b2a4a7",
        strip_prefix = "cross-media-measurement-api-0.42.0",
        url = "https://github.com/world-federation-of-advertisers/cross-media-measurement-api/archive/refs/tags/v0.42.0.tar.gz",
    )
