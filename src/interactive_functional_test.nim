#
# Nim libu2f - functional tests
#
# Copyright 2017 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file
#

import strutils, unittest
import os, json
import tables

import libu2f_host
import libu2f_server

const
  origin = "http://127.0.0.1:5000"
  app_id = "http://127.0.0.1:5000"

proc check_format(msg: string, checks: openArray[(string, int)]) =
  ## Check keys and values len
  let j = parseJson(msg)
  for c in checks:
    let (name, length) = c
    if not j.hasKey(name):
      echo "Warning: key '$#' is missing" % name
    elif length != -1 and j[name].str.len != length:
      echo "Warning: key '$#' has len $# - expected $#" % [name,
        $j[name].str.len, $length]

  if j.len > checks.len:
    echo "Warning: extra keys in msg:"
    echo $msg
    echo "---"


suite "Functional test":

  # Initialization

  let srv_ctx = newU2FServerCtx(app_id, origin)
  let srv_ctx2 = newU2FServerCtx(app_id, origin)
  let host_ctx = newU2FHostCtx()

  var msg = ""
  var msg2 = ""
  var key_handle = ""

  # Registration using 2 server contexts

  test "Server: Create registration challenge":
    msg = srv_ctx.registration_challenge()
    check_format(msg, {"challenge": 43, "version": 6, "appId": 21})

  test "Server2: Create registration challenge":
    msg2 = srv_ctx2.registration_challenge()
    check_format(msg2, {"challenge": 43, "version": 6, "appId": 21})

  test "Compare registration challenges":
    let
      j = parseJson(msg)
      j2 = parseJson(msg2)
    assert j["challenge"] != j2["challenge"]

  test "Host: Respond to registration challenge":
    echo "Press now!"
    msg2 = host_ctx.register(msg2, origin)
    check_format(msg2, {"registrationData": -1, "clientData": 186})

  test "Host: Respond to registration challenge":
    echo "Press now!"
    msg = host_ctx.register(msg, origin)
    check_format(msg, {"registrationData": -1, "clientData": 186})

  test "Compare registration":
    let
      j = parseJson(msg)
      j2 = parseJson(msg2)
    assert j["registrationData"] != j2["registrationData"]
    assert j["clientData"] != j2["clientData"]

  test "Server: Verify registration":
    key_handle = srv_ctx.verify_registration(msg)

  test "Server: Verify registration":
    key_handle = srv_ctx2.verify_registration(msg2)



  # Login

  test "Server: Generate login challenge":
    msg = srv_ctx.generate_authentication_challenge(key_handle)
    check_format(msg, {"keyHandle": 86, "version": 6, "challenge": 43, "appId": 21})

  test "Host: Respond to login challenge":
    echo "Press now!"
    msg = host_ctx.authenticate(msg, origin)

  # signatureData clientData keyHandle

  test "Server: Verify login":
    srv_ctx.verify_authentication(msg)

  test "Server: Verify login":
    srv_ctx.verify_authentication(msg)

  test "Destructors":
    srv_ctx.done()
    srv_ctx2.done()
    #host_ctx.done()

  echo "Test done."
