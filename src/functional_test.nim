#
# Nim libu2f - functional tests
#
# Copyright 2017 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file
#

import strutils, unittest
import os, json
import tables

import libu2f_server

const
  origin = "http://demo.yubico.com"
  app_id = "http://demo.yubico.com"

proc check_format(msg: string, checks: openArray[(string, int)]) =
  ##
  let j = parseJson(msg)
  for c in checks:
    let (name, length) = c
    if not j.hasKey(name):
      echo "Warning: key '$#' is missing" % name
    elif j[name].str.len != length:
      echo "Warning: key '$#' has len $# - expected $#" % [name,
        $j[name].str.len, $length]

  if j.len > checks.len:
    echo "Warning: extra keys in msg:"
    echo $msg
    echo "---"

proc hexDump(s: string | cstring): string =
  result = newStringOfCap(s.len * 2)
  for c in s:
    result.add toHex(ord(c), 2)

proc fromHex(s: string): string =
  result = newString(s.len div 2)
  for p in 0..result.len:
    let i = s[p*2..(p*2 + 1)].parseHexInt
    result[p] = chr(i)



suite "Functional test":

  # Initialization

  let srv_ctx = newU2FServerCtx(app_id, origin)

  # Registration

  test "hex":
    assert "00112233fF".fromHex.hexDump == "00112233FF"

  test "Server: Create registration challenge":
    let msg = srv_ctx.registration_challenge()
    check_format(msg, {"challenge": 43, "version": 6, "appId": 22})

  test "Server: Set invalid challenge":
    expect U2FServerError:
      srv_ctx.set_challenge "bogus"

  test "Server: Verify registration":
    const
      reg_resp = """{ "registrationData": "BQRcbdE4PHGRaJUTK9hY4GrX_jZa5eWgjJK6IfwezrndHvQi7QQtYA2qAg4NrebNkSCoOwJ0V1PzLlP1Wr_Oku_0QKfeNR0Ei4_I40GCo5xjm4Q7hnZwzXQ5f5vjtnx7xIqCZ-z7GOGExeouBXxaMgleYpX7xMR6Y9wa_qzLLTAr6IcwggIbMIIBBaADAgECAgR1o_Z1MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk3MzY3OTczMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBmjfkNqa2mXzVh2ZxuES5coCvvENxDMDLmfd-0ACG0Fu7wR4ZTjKd9KAuidySpfona5csGmlM0Te_Zu35h_wwujEjAQMA4GCisGAQQBgsQKAQIEADALBgkqhkiG9w0BAQsDggEBAb0tuI0-CzSxBg4cAlyD6UyT4cKyJZGVhWdtPgj_mWepT3Tu9jXtdgA5F3jfZtTc2eGxuS-PPvqRAkZd40AXgM8A0YaXPwlT4s0RUTY9Y8aAQzQZeAHuZk3lKKd_LUCg5077dzdt90lC5eVTEduj6cOnHEqnOr2Cv75FuiQXX7QkGQxtoD-otgvhZ2Fjk29o7Iy9ik7ewHGXOfoVw_ruGWi0YfXBTuqEJ6H666vvMN4BZWHtzhC0k5ceQslB9Xdntky-GQgDqNkkBf32GKwAFT9JJrkO2BfsB-wfBrTiHr0AABYNTNKTceA5dtR3UVpI492VUWQbY3YmWUUfKTI7fM4wRQIhAN3c-VHubCCkUtZXfWL1aiEXU1qWRiM_ayKmWLUafyFbAiARTwlVocoamd9S-cYBosRKso_XGAPzAedzpuE2tEjp1g==", "clientData": "eyAiY2hhbGxlbmdlIjogIllTMTludV9ZWWpnczI5WndrU3dRb2JyNzhPaURXRnoxeXFZZW85WUpmQnciLCAib3JpZ2luIjogImh0dHA6XC9cL2RlbW8ueXViaWNvLmNvbSIsICJ0eXAiOiAibmF2aWdhdG9yLmlkLmZpbmlzaEVucm9sbG1lbnQiIH0=" }"""
      expected_key_handle = "p941HQSLj8jjQYKjnGObhDuGdnDNdDl_m-O2fHvEioJn7PsY4YTF6i4FfFoyCV5ilfvExHpj3Br-rMstMCvohw"
      challenge = "YS19nu_YYjgs29ZwkSwQobr78OiDWFz1yqYeo9YJfBw"
      expected_pubkey = "045C6DD1383C71916895132BD858E06AD7FE365AE5E5A08C92BA21FC1ECEB9DD1EF422ED042D600DAA020E0DADE6CD9120A83B02745753F32E53F55ABFCE92EFF4"

    srv_ctx.set_challenge challenge
    let (key_handle, public_key) = srv_ctx.verify_registration2(reg_resp)

    assert key_handle == expected_key_handle
    assert public_key.hexDump == expected_pubkey

    expect U2FServerError:
      srv_ctx.set_challenge "YS19nu_YYjgs29ZwkSwQobr78OiDWFz1yqYeo9YJfBB" # Wrong challenge
      discard srv_ctx.verify_registration2(reg_resp)


  # Login

  test "Server: Generate login challenge":
    const
      key_handle = "p941HQSLj8jjQYKjnGObhDuGdnDNdDl_m-O2fHvEioJn7PsY4YTF6i4FfFoyCV5ilfvExHpj3Br-rMstMCvohw"
      challenge = "YS19nu_YYjgs29ZwkSwQobr78OiDWFz1yqYeo9YJfBw"
      expected_msg = """{ "keyHandle": "p941HQSLj8jjQYKjnGObhDuGdnDNdDl_m-O2fHvEioJn7PsY4YTF6i4FfFoyCV5ilfvExHpj3Br-rMstMCvohw", "version": "U2F_V2", "challenge": "YS19nu_YYjgs29ZwkSwQobr78OiDWFz1yqYeo9YJfBw", "appId": "http:\/\/demo.yubico.com" }"""

    srv_ctx.set_challenge challenge
    assert srv_ctx.generate_authentication_challenge(key_handle) == expected_msg

  test "Server: Verify authentication":
    const
      challenge = "v31IKBFdLkdN_Z9tXfAxydupofCf89k6A4a7to0OjTo"
      key_handle = "kAbb2p57pxHg2mY8y_Kgcdc7jnnAoncJm8vOgqfigyWTvPGFlvxA04ULD9IJ-KpSyn733LRbJ-CG573N9jCY1g"
      resp = """{ "signatureData": "AQAAACYwRAIgXUFB4phCuqcc0-a9obD8S_eMuMJbTC0_VrWizmwHadECIAXb_GaAEIuAJv806eUvMjc2Qi-ii5IMbNw2YU2t39Wp", "clientData": "eyAiY2hhbGxlbmdlIjogInYzMUlLQkZkTGtkTl9aOXRYZkF4eWR1cG9mQ2Y4OWs2QTRhN3RvME9qVG8iLCAib3JpZ2luIjogImh0dHA6XC9cL2RlbW8ueXViaWNvLmNvbSIsICJ0eXAiOiAibmF2aWdhdG9yLmlkLmdldEFzc2VydGlvbiIgfQ==", "keyHandle": "kAbb2p57pxHg2mY8y_Kgcdc7jnnAoncJm8vOgqfigyWTvPGFlvxA04ULD9IJ-KpSyn733LRbJ-CG573N9jCY1g" }"""
      pub_key = "0414c32e410b309d6e937f8b5d81f9e564fd112ce5fef0105efbecd55554522525e454290ff42ea1d877193612e36e39179124b5938ee0fef369acb94c379783cb"


    let srv_ctx = newU2FServerCtx(app_id, origin)
    srv_ctx.set_challenge challenge
    srv_ctx.set_key_handle key_handle

    expect U2FServerError:
      # Public key not set
      srv_ctx.verify_authentication(resp)

    srv_ctx.set_public_key(fromHex(pub_key))
    srv_ctx.verify_authentication(resp)


  echo "Test done."
