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
        sha256 = "ac63eff9ec91e698fc002b2f643cde087ced579f613e74c4cc5e32a6a89933a2",
        # TODO(world-federation-of-advertisers/common-jvm#218): Use version.
        strip_prefix = "common-jvm-136c829fddddbc4396e3ac25b3d7fa72dd485a1d",
        url = "https://github.com/world-federation-of-advertisers/common-jvm/archive/136c829fddddbc4396e3ac25b3d7fa72dd485a1d.tar.gz",
    )

    http_archive(
        name = "wfa_measurement_proto",
        sha256 = "3f4d4dd360f55e9c0fe033e86191f3d7c1187611650ef08c6a299ce917eb4b77",
        # TODO(world-federation-of-advertisers/cross-media-measurement-api#177): Use version.
        strip_prefix = "cross-media-measurement-api-e2b2cf0f1b6867658dd446d31fe0b1bc16897f86",
        url = "https://github.com/world-federation-of-advertisers/cross-media-measurement-api/archive/e2b2cf0f1b6867658dd446d31fe0b1bc16897f86.tar.gz",
    )
