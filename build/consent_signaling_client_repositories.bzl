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
        sha256 = "7c214180e4777b583718f48584213ecb8ba37f2d68639b02b9bd44d0bae42a9a",
        # DO_NOT_SUBMIT(world-federation-of-advertisers/common-jvm#219): Use version.
        strip_prefix = "common-jvm-408a1a890b350c20e89377ef3c6c3de568650bb2",
        url = "https://github.com/world-federation-of-advertisers/common-jvm/archive/408a1a890b350c20e89377ef3c6c3de568650bb2.tar.gz",
    )

    http_archive(
        name = "wfa_measurement_proto",
        sha256 = "e1b9555af5df07ef4a9e02122bf2591aeae01627c0f982808e5fea4e2117269d",
        # DO_NOT_SUBMIT(world-federation-of-advertisers/cross-media-measurement-api#185): Use version.
        strip_prefix = "cross-media-measurement-api-6626300a854eaece1555dbf7345cdd4d8b13d437",
        url = "https://github.com/world-federation-of-advertisers/cross-media-measurement-api/archive/6626300a854eaece1555dbf7345cdd4d8b13d437.tar.gz",
    )
