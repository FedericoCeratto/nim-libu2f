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

  u2fh_rc* {.size: sizeof(cint).} = enum
    U2FH_SIZE_ERROR = -8, U2FH_TIMEOUT_ERROR = -7,
    U2FH_AUTHENTICATOR_ERROR = -6, U2FH_NO_U2F_DEVICE = -5,
    U2FH_BASE64_ERROR = -4, U2FH_JSON_ERROR = -3,
    U2FH_TRANSPORT_ERROR = -2, U2FH_MEMORY_ERROR = -1,
    U2FH_OK = 0

  #u2fh_cmdflags = int
  u2fh_cmdflags {.size: sizeof(cint).} = enum
    NONE = 0, REQUEST_USER_PRESENCE = 1


proc u2fh_global_init*(flags: u2fh_initflags): u2fh_rc
  {.cdecl, importc: "u2fh_global_init", dynlib: lib_fn.}

proc u2fh_global_done*()
  {.cdecl, importc: "u2fh_global_done", dynlib: lib_fn.}

proc u2fh_strerror*(err: cint): cstring
  {.cdecl, importc: "u2fh_strerror", dynlib: lib_fn.}

proc u2fh_strerror_name*(err: cint): cstring
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


proc chk(outcode: u2fh_rc) =
  if outcode != U2FH_OK:
    raise newException(Exception, "U2F Error: $#" % $outcode)

# Exported procs

proc newU2FHostCtx*(): U2FHostCtx =
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
  ##
  var response: cstringArray = allocCStringArray(@[""])
  chk ctx.pdevs.u2fh_authenticate(challenge.cstring, origin.cstring, response,
    u2fh_cmdflags.REQUEST_USER_PRESENCE)
  let resp = cstringArrayToSeq(response)
  if resp.len != 1:
    echo "WRONG LEN"

  return resp[0]
