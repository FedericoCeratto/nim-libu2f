#
# Nim libu2f - interactive server and host functional tests
#
# Copyright 2017 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file
#

import strutils, unittest
import os, json
import tables

from functional_test import check_format

import libu2f_host
import libu2f_server

const
  origin = "http://127.0.0.1:5000"
  app_id = "http://127.0.0.1:5000"



suite "Interactive functional test":

  # Initialization

  let srv_ctx = newU2FServerCtx(app_id, origin)
  let srv_ctx2 = newU2FServerCtx(app_id, origin)
  let host_ctx = newU2FHostCtx()

  var msg = ""
  var msg2 = ""
  var login_data: U2FLoginData
  var login_data2: U2FLoginData

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
    login_data = srv_ctx.verify_registration(msg)

  test "Server: Verify registration":
    login_data2 = srv_ctx2.verify_registration(msg2)


  # Login

  test "Server: Generate login challenge":
    msg = srv_ctx.generate_authentication_challenge(login_data.key_handle)
    check_format(msg, {"keyHandle": 86, "version": 6, "challenge": 43, "appId": 21})

  test "Server: Generate login challenge":
    msg2 = srv_ctx2.generate_authentication_challenge(login_data.key_handle)
    check_format(msg2, {"keyHandle": 86, "version": 6, "challenge": 43, "appId": 21})


  test "Host: Respond to login challenge":
    echo "Press now!"
    msg = host_ctx.authenticate(msg, origin)

  test "Host: Respond to login challenge":
    echo "Press now!"
    msg2 = host_ctx.authenticate(msg2, origin)


  test "Server: Verify login":
    srv_ctx.set_public_key(login_data.public_key)
    srv_ctx.verify_authentication(msg)

  test "Server: Verify login":
    srv_ctx2.set_public_key(login_data.public_key)
    srv_ctx2.verify_authentication(msg2)


  test "Destructors":
    srv_ctx.done()
    srv_ctx2.done()
    host_ctx.done()

  echo "Test done."
