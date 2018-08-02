// Copyright 2013 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11

/*
#cgo windows CFLAGS: -DREPACK_STRUCTURES

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ltdl.h>
#include <unistd.h>
#include "pkcs11go.h"

struct ctx {
	lt_dlhandle handle;
	CK_FUNCTION_LIST_PTR sym;
};

#define CKM_BIP32_MASTER_DERIVE (CKM_VENDOR_DEFINED + 0xE00)
#define CKM_BIP32_CHILD_DERIVE (CKM_VENDOR_DEFINED + 0xE01)

typedef struct CK_BIP32_MASTER_DERIVE_PARAMS {
  CK_ATTRIBUTE_PTR pPublicKeyTemplate;
  CK_ULONG         ulPublicKeyAttributeCount;
  CK_ATTRIBUTE_PTR pPrivateKeyTemplate;
  CK_ULONG         ulPrivateKeyAttributeCount;
  CK_OBJECT_HANDLE hPublicKey; // output parameter
  CK_OBJECT_HANDLE hPrivateKey; // output parameter
} CK_BIP32_MASTER_DERIVE_PARAMS;

typedef struct CK_BIP32_CHILD_DERIVE_PARAMS {
  CK_ATTRIBUTE_PTR pPublicKeyTemplate;
  CK_ULONG         ulPublicKeyAttributeCount;
  CK_ATTRIBUTE_PTR pPrivateKeyTemplate;
  CK_ULONG         ulPrivateKeyAttributeCount;
  CK_ULONG_PTR     pulPath;
  CK_ULONG         ulPathLen;
  CK_OBJECT_HANDLE hPublicKey; // output parameter
  CK_OBJECT_HANDLE hPrivateKey; // output parameter
  CK_ULONG         ulPathErrorIndex; // output parameter
} CK_BIP32_CHILD_DERIVE_PARAMS;

CK_RV DeriveBIP32Master(struct ctx * c, CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE basekey,
    CK_ATTRIBUTE_PTR aPub, CK_ULONG alenPub,
    CK_ATTRIBUTE_PTR aPriv, CK_ULONG alenPriv,
    CK_OBJECT_HANDLE_PTR publicKey, CK_OBJECT_HANDLE_PTR privateKey)
{
  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_BIP32_MASTER_DERIVE;

  CK_BIP32_MASTER_DERIVE_PARAMS params;
  params.pPublicKeyTemplate = aPub;
  params.ulPublicKeyAttributeCount = alenPub;
  params.pPrivateKeyTemplate = aPriv;
  params.ulPrivateKeyAttributeCount = alenPriv;
  params.hPublicKey = 0;
  params.hPrivateKey = 0;

  mechanism.pParameter = &params;
  mechanism.ulParameterLen = sizeof(params);

  CK_RV e = c->sym->C_DeriveKey(session, &mechanism, basekey, NULL, 0, NULL);
  *publicKey = params.hPublicKey;
  *privateKey = params.hPrivateKey;
  return e;
}

CK_RV DeriveBIP32Child(struct ctx * c, CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE basekey,
    CK_ATTRIBUTE_PTR aPub, CK_ULONG alenPub,
    CK_ATTRIBUTE_PTR aPriv, CK_ULONG alenPriv, CK_ULONG_PTR path, CK_ULONG pathLen,
    CK_OBJECT_HANDLE_PTR publicKey, CK_OBJECT_HANDLE_PTR privateKey, CK_ULONG_PTR pathErrorIndex)
{
  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_BIP32_CHILD_DERIVE;

  CK_BIP32_CHILD_DERIVE_PARAMS params;
  params.pPublicKeyTemplate = aPub;
  params.ulPublicKeyAttributeCount = alenPub;
  params.pPrivateKeyTemplate = aPriv;
  params.ulPrivateKeyAttributeCount = alenPriv;
  params.pulPath = path;
  params.ulPathLen = pathLen;
  params.hPublicKey = 0;
  params.hPrivateKey = 0;
  params.ulPathErrorIndex = 0;

  mechanism.pParameter = &params;
  mechanism.ulParameterLen = sizeof(params);

  CK_RV e = c->sym->C_DeriveKey(session, &mechanism, basekey, NULL, 0, NULL);
  *publicKey = params.hPublicKey;
  *privateKey = params.hPrivateKey;
  *pathErrorIndex = params.ulPathErrorIndex;
  return e;
}

*/
import "C"

func (c *Ctx) DeriveBIP32MasterKeys(sh SessionHandle, basekey ObjectHandle, publicAttr []*Attribute, privateAttr []*Attribute) (ObjectHandle, ObjectHandle, error) {
  var publicKey C.CK_OBJECT_HANDLE
  var privateKey C.CK_OBJECT_HANDLE
  publicAttrArena, publicAttrC, publicAttrLen := cAttributeList(publicAttr)
  defer publicAttrArena.Free()
  privateAttrArena, privateAttrC, privateAttrLen := cAttributeList(privateAttr)
  defer privateAttrArena.Free()
  e := C.DeriveBIP32Master(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(basekey), publicAttrC, publicAttrLen, privateAttrC, privateAttrLen, &publicKey, &privateKey)
  return ObjectHandle(publicKey), ObjectHandle(privateKey), toError(e)
}

func (c *Ctx) DeriveBIP32ChildKeys(sh SessionHandle, basekey ObjectHandle, publicAttr []*Attribute, privateAttr []*Attribute, path []uint32) (ObjectHandle, ObjectHandle, uint, error) {
  var publicKey C.CK_OBJECT_HANDLE
  var privateKey C.CK_OBJECT_HANDLE
  var pathErrorIndex C.CK_ULONG
  publicAttrArena, publicAttrC, publicAttrLen := cAttributeList(publicAttr)
  defer publicAttrArena.Free()
  privateAttrArena, privateAttrC, privateAttrLen := cAttributeList(privateAttr)
  defer privateAttrArena.Free()
  cPath := make([]C.CK_ULONG, len(path))
  for i := 0; i < len(path); i++ {
    cPath[i] = C.CK_ULONG(path[i])
  }
  e := C.DeriveBIP32Child(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(basekey), publicAttrC, publicAttrLen, privateAttrC, privateAttrLen, &cPath[0], C.CK_ULONG(len(path)), &publicKey, &privateKey, &pathErrorIndex)
  return ObjectHandle(publicKey), ObjectHandle(privateKey), uint(pathErrorIndex), toError(e)
}
