#
# Nim libu2f host/client side
#
# Copyright 2017 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file
#

import strutils

const lib_fn* = "libu2f-host.so.0"

type
  u2fh_initflags = int
  u2fh_devs = pointer
  U2FHostCtx* = object of RootObj
    devs: pointer
    pdevs: ptr u2fh_devs

  u2fh_rc* {.pure, size: sizeof(cint).} = enum
    SIZE_ERROR = -8, TIMEOUT_ERROR = -7,
    AUTHENTICATOR_ERROR = -6, NO_U2F_DEVICE = -5,
    BASE64_ERROR = -4, JSON_ERROR = -3,
    TRANSPORT_ERROR = -2, MEMORY_ERROR = -1,
    OK = 0
  U2FHostError* = object of Exception

  u2fh_cmdflags {.size: sizeof(cint).} = enum
    NONE = 0, REQUEST_USER_PRESENCE = 1


proc u2fh_global_init*(flags: u2fh_initflags): u2fh_rc
  {.cdecl, importc: "u2fh_global_init", dynlib: lib_fn.}

proc u2fh_global_done*()
  {.cdecl, importc: "u2fh_global_done", dynlib: lib_fn.}

proc u2fh_strerror*(err: u2fh_rc): cstring
  {.cdecl, importc: "u2fh_strerror", dynlib: lib_fn.}

proc u2fh_strerror_name*(err: u2fh_rc): cstring
  {.cdecl, importc: "u2fh_strerror_name", dynlib: lib_fn.}

proc u2fh_devs_init*(devs: ptr ptr u2fh_devs): u2fh_rc
  {.cdecl, importc: "u2fh_devs_init", dynlib: lib_fn.}

proc u2fh_devs_discover*(devs: ptr u2fh_devs; max_index: ptr cuint): u2fh_rc
  {.cdecl, importc: "u2fh_devs_discover", dynlib: lib_fn.}

proc u2fh_devs_done*(devs: ptr u2fh_devs)
  {.cdecl, importc: "u2fh_devs_done", dynlib: lib_fn.}

proc u2fh_register*(devs: ptr u2fh_devs; challenge: cstring; origin: cstring;
                    response: cstringArray; flags: u2fh_cmdflags): u2fh_rc
  {. cdecl, importc: "u2fh_register", dynlib: lib_fn.}

proc u2fh_register2*(devs: ptr u2fh_devs; challenge: cstring; origin: cstring;
                     response: cstring; response_len: ptr csize;
                     flags: u2fh_cmdflags): u2fh_rc
  {.cdecl, importc: "u2fh_register2", dynlib: lib_fn.}

proc u2fh_authenticate*(devs: ptr u2fh_devs; challenge: cstring;
                        origin: cstring; response: cstringArray;
                        flags: u2fh_cmdflags): u2fh_rc
  {.cdecl, importc: "u2fh_authenticate", dynlib: lib_fn.}

proc u2fh_authenticate2*(devs: ptr u2fh_devs; challenge: cstring;
                         origin: cstring; response: cstring;
                         response_len: ptr csize; flags: u2fh_cmdflags): u2fh_rc
  {.cdecl, importc: "u2fh_authenticate2", dynlib: lib_fn.}

proc u2fh_sendrecv*(devs: ptr u2fh_devs; index: cuint; cmd: uint8;
                    send: ptr cuchar; sendlen: uint16; recv: ptr cuchar;
                    recvlen: ptr csize): u2fh_rc
  {.cdecl, importc: "u2fh_sendrecv", dynlib: lib_fn.}

proc u2fh_get_device_description*(devs: ptr u2fh_devs; index: cuint;
                                  `out`: cstring; len: ptr csize): u2fh_rc
  {.cdecl, importc: "u2fh_get_device_description", dynlib: lib_fn.}

proc u2fh_is_alive*(devs: ptr u2fh_devs; index: cuint): cint
  {.cdecl, importc: "u2fh_is_alive", dynlib: lib_fn.}


template chk(outcode: u2fh_rc) =
  if outcode != u2fh_rc.OK:
    let err_msg = $u2fh_strerror(outcode)
    raise newException(U2FHostError, "U2F Error: $#" % $err_msg)

# Exported procs

proc newU2FHostCtx*(): U2FHostCtx =
  ## Initialize U2F host context
  result = U2FHostCtx()
  chk u2fh_global_init(0)
  var nyan: ptr u2fh_devs
  chk u2fh_devs_init(addr(nyan))
  var max_index = cuint(1000)
  chk u2fh_devs_discover(nyan, max_index.addr)
  result.pdevs = nyan

proc register*(ctx: U2FHostCtx, challenge, origin: string): string =
  ## Register token
  var response: cstringArray = allocCStringArray(@[""])
  chk ctx.pdevs.u2fh_register(challenge.cstring, origin.cstring, response,
    u2fh_cmdflags.REQUEST_USER_PRESENCE)
  return cstringArrayToSeq(response)[0]

proc authenticate*(ctx: U2FHostCtx, challenge, origin: string): string =
  ## Authenticate
  var response: cstringArray = allocCStringArray(@[""])
  chk ctx.pdevs.u2fh_authenticate(challenge.cstring, origin.cstring, response,
    u2fh_cmdflags.REQUEST_USER_PRESENCE)
  let resp = cstringArrayToSeq(response)
  assert resp.len == 1
  return resp[0]

proc done*(ctx: U2FHostCtx) =
  ## U2F host context destructor
  ctx.pdevs.u2fh_devs_done()
