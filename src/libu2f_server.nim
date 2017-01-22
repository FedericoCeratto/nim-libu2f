#
# Nim libu2f server side
#
# Copyright 2017 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv3 License, see LICENSE file
#

import strutils

const
  U2FS_CHALLENGE_RAW_LEN = 32
  U2FS_CHALLENGE_B64U_LEN = 43
  U2FS_PUBLIC_KEY_LEN = 65
  U2FS_COUNTER_LEN = 4

  lib_fn* = "libu2f-server.so.0"

##  Error codes:
##
##  OK: Success.
##  MEMORY_ERROR: Memory error.
##  JSON_ERROR: Json error.
##  BASE64_ERROR: Base64 error.
##  CRYPTO_ERROR: Cryptographic error.
##  ORIGIN_ERROR: Origin mismatch.
##  CHALLENGE_ERROR: Challenge error.
##  SIGNATURE_ERROR: Signature mismatch.
##  FORMAT_ERROR: Message format error.

type
  u2fs_rc* {.pure, size: sizeof(cint).} = enum
    FORMAT_ERROR = - 8, SIGNATURE_ERROR = - 7,
    CHALLENGE_ERROR = - 6, ORIGIN_ERROR = - 5,
    CRYPTO_ERROR = - 4, BASE64_ERROR = - 3, JSON_ERROR = - 2,
    MEMORY_ERROR = - 1, OK = 0
  U2FServerError* = object of Exception

  u2fs_initflags {.pure, size: sizeof(cint).} = enum
    NONE = 0, DEBUG = 1
  u2fs_ctx_t = int
  u2fs_reg_res_t = int
  RegistrationResponse = ptr u2fs_reg_res_t
  u2fs_auth_res_t = int
  AuthenticationResponse = ptr u2fs_auth_res_t
  U2FServerCtx = ptr u2fs_ctx_t
  KeyHandle* = string
  PublicKey* = string
  U2FLoginData* = tuple[key_handle: KeyHandle, public_key: PublicKey]


proc u2fs_global_init(flags: u2fs_initflags): u2fs_rc
  {.cdecl, importc: "u2fs_global_init", dynlib: lib_fn.}

proc u2fs_global_done*()
  {.cdecl, importc: "u2fs_global_done", dynlib: lib_fn.}

# Error handling

proc u2fs_strerror(err: u2fs_rc): cstring
  {.cdecl, importc: "u2fs_strerror", dynlib: lib_fn.}

proc u2fs_strerror_name*(err: cint): cstring
  {.cdecl, importc: "u2fs_strerror_name", dynlib: lib_fn.}

# Create context before registration/authentication calls.

proc u2fs_init(ctx: ptr U2FServerCtx): u2fs_rc
  {.cdecl, importc: "u2fs_init", dynlib: lib_fn.}

proc u2fs_done(ctx: U2FServerCtx)
  {.cdecl, importc: "u2fs_done", dynlib: lib_fn.}

proc u2fs_set_origin*(ctx: U2FServerCtx; origin: cstring): u2fs_rc
  {.cdecl, importc: "u2fs_set_origin", dynlib: lib_fn.}

proc u2fs_set_appid*(ctx: U2FServerCtx; appid: cstring): u2fs_rc
  {.cdecl, importc: "u2fs_set_appid", dynlib: lib_fn.}

proc u2fs_set_challenge*(ctx: U2FServerCtx; challenge: cstring): u2fs_rc
  {.cdecl, importc: "u2fs_set_challenge", dynlib: lib_fn.}

proc u2fs_set_keyHandle*(ctx: U2FServerCtx; keyHandle: cstring): u2fs_rc
  {.cdecl, importc: "u2fs_set_keyHandle", dynlib: lib_fn.}

proc u2fs_set_publicKey*(ctx: U2FServerCtx; publicKey: ptr cuchar): u2fs_rc
  {.cdecl, importc: "u2fs_set_publicKey", dynlib: lib_fn.}

# Registration functions

proc u2fs_registration_challenge*(ctx: U2FServerCtx; output: ptr cstring): u2fs_rc
  {.cdecl, importc: "u2fs_registration_challenge", dynlib: lib_fn.}

proc u2fs_registration_verify*(ctx: U2FServerCtx; response: cstring;
                               output: ptr RegistrationResponse): u2fs_rc
  {.cdecl,
    importc: "u2fs_registration_verify", dynlib: lib_fn.}

proc u2fs_get_registration_keyHandle*(result: RegistrationResponse): cstring
  {.cdecl, importc: "u2fs_get_registration_keyHandle", dynlib: lib_fn.}

proc u2fs_get_registration_publicKey(result: RegistrationResponse): cstring
  {.cdecl, importc: "u2fs_get_registration_publicKey", dynlib: lib_fn.}

proc u2fs_free_reg_res*(result: RegistrationResponse)
  {.cdecl, importc: "u2fs_free_reg_res", dynlib: lib_fn.}

# Authentication functions

proc u2fs_authentication_challenge*(ctx: U2FServerCtx; output: ptr cstring): u2fs_rc
  {.cdecl, importc: "u2fs_authentication_challenge", dynlib: lib_fn.}

proc u2fs_authentication_verify*(ctx: U2FServerCtx; response: cstring;
                                 output: ptr AuthenticationResponse): u2fs_rc
  {.cdecl, importc: "u2fs_authentication_verify", dynlib: lib_fn.}

proc u2fs_get_authentication_result*(result: AuthenticationResponse;
                                     verified: ptr u2fs_rc;
                                     counter: ptr uint32;
                                     user_presence: ptr uint8): u2fs_rc
  {.cdecl, importc: "u2fs_get_authentication_result", dynlib: lib_fn.}

proc u2fs_free_auth_res*(result: AuthenticationResponse)
  {.cdecl, importc: "u2fs_free_auth_res", dynlib: lib_fn.}


template chk(outcode: u2fs_rc) =
  if outcode != u2fs_rc.OK:
    let err_msg = $u2fs_strerror(outcode)
    raise newException(U2FServerError, "U2F Error: $#" % $err_msg)

# Exported procs

proc newU2FServerCtx*(appid, origin: string, debug = false): U2FServerCtx =
  ## Initialize U2F server context
  var result: U2FServerCtx
  chk u2fs_global_init(if debug: u2fs_initflags.DEBUG else: u2fs_initflags.NONE)
  chk u2fs_init(addr(result))
  chk result.u2fs_set_appid(appid.cstring)
  chk result.u2fs_set_origin(origin.cstring)
  return result

proc registration_challenge*(ctx: U2FServerCtx): string =
  ##
  var challenge = "".cstring
  chk ctx.u2fs_registration_challenge(addr(challenge))
  let ret = $challenge
  return ret

proc verify_registration*(ctx: U2FServerCtx, challenge: string): U2FLoginData =
  ## Verify registration and return key handle and public key.
  ## Store them on the server and they will be needed to authenticate.
  const bufsize = 2048
  var output: RegistrationResponse = create(u2fs_reg_res_t, bufsize)
  let u2fresponse = challenge.cstring
  chk ctx.u2fs_registration_verify(u2fresponse.cstring, addr output)
  let key_handle: KeyHandle = $u2fs_get_registration_keyHandle(output)
  let pkc = u2fs_get_registration_publicKey(output)
  var pk: PublicKey = newString(U2FS_PUBLIC_KEY_LEN)
  copyMem(addr pk[0], pkc, U2FS_PUBLIC_KEY_LEN)
  return (key_handle, pk)

template cpt(target: string): expr =
  cast[ptr cuchar](cstring(target))

proc set_public_key*(ctx: U2FServerCtx, public_key: string) =
  ## Set public key
  assert public_key.len == U2FS_PUBLIC_KEY_LEN
  chk ctx.u2fs_set_publicKey(cpt public_key)

proc generate_authentication_challenge*(ctx: U2FServerCtx, key_handle: string): string =
  ## Generate authentication challenge
  chk ctx.u2fs_set_keyHandle(key_handle.cstring)
  var challenge = cstring("")
  chk ctx.u2fs_authentication_challenge(addr(challenge))
  let ret = $challenge
  return ret

proc verify_authentication*(ctx: U2FServerCtx, auth_msg: string) =
  ## Verify authentication challenge
  var nyan: ptr u2fs_auth_res_t = create(u2fs_auth_res_t, 1)
  var output: AuthenticationResponse = nyan
  chk ctx.u2fs_authentication_verify(auth_msg.cstring, addr output)
  u2fs_free_auth_res(output)

proc set_challenge*(ctx: U2FServerCtx; challenge: string) =
  ## Set challenge
  chk ctx.u2fs_set_challenge(challenge)

proc set_key_handle*(ctx: U2FServerCtx, key_handle: string) =
  ## Set key handle
  chk ctx.u2fs_set_keyHandle(key_handle.cstring)

proc done*(ctx: U2FServerCtx) =
  ## U2F server context destructor
  ctx.u2fs_done()
