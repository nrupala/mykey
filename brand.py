# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2026 2351485 ALBERTA INC.

"""Brand configuration — the ONLY place brand strings live.

Rename-on-the-fly guarantee (owner directive, 2026-10-12): if the
product name ever has to change, it changes HERE and nowhere else.
The vault engine, CLI and GUI read every brand string from this
module; the cryptography never reads it at all, so a rename cannot
affect any existing vault.

Every value can be overridden by environment variable at runtime,
which is also how the brand-swap test exercises a rename.
"""

import os

PRODUCT_NAME = os.environ.get("MYKEY_PRODUCT_NAME", "MyKey")
PRODUCT_TAGLINE = os.environ.get(
    "MYKEY_PRODUCT_TAGLINE", "Zero-Trust Password Manager"
)
DOMAIN = os.environ.get("MYKEY_DOMAIN", "usemykey.com")
SUPPORT_EMAIL = os.environ.get("MYKEY_SUPPORT_EMAIL", "info@aimlds.org")
APP_ID = os.environ.get("MYKEY_APP_ID", "com.usemykey.mykey")
VENDOR_NAME = os.environ.get("MYKEY_VENDOR_NAME", "2351485 ALBERTA INC.")
ATTRIBUTION = os.environ.get(
    "MYKEY_ATTRIBUTION", "Owned by Nrupal Akolkar · Built with Muse by Meta"
)
# Licence purchase + tip destinations. These are configuration,
# not a checkout: the product site behind them is a separate piece
# and the apps only ever link to these constants.
LICENCE_BUY_URL = os.environ.get(
    "MYKEY_LICENCE_BUY_URL", f"https://{DOMAIN}/buy"
)
TIP_URL = os.environ.get("MYKEY_TIP_URL", f"https://{DOMAIN}/tip")
