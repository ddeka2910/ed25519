// Copyright 2013 The Go Authors. All rights reserved.  Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// Package ed25519 implements the Ed25519 signature algorithm. See
// http://ed25519.cr.yp.to/.
package ed25519

// This code is a port of the public domain, "ref10" implementation of ed25519
// from SUPERCOP.

import (
	"bytes"
	"crypto/sha512"
)

type (
	// PublicKey contains an ed25519 public key. The key will always be
	// 'PublicKeySize' in length.
	PublicKey []byte

	// SecretKey contains an ed25519 secret key. The key will always be
	// 'SecretKeySize' in length.
	SecretKey []byte

	// Signature contains an ed25519 signature. The signature will always be
	// 'SignatureSize' in length.
	Signature []byte
)

// GenerateKey generates a public/secret key pair using randomness from rand.
func GenerateKey(entropy [EntropySize]byte) (SecretKey, PublicKey) {
	secretKey := SecretKey(make([]byte, SecretKeySize))
	copy(secretKey[:], entropy[:])

	h := sha512.New()
	h.Write(secretKey[:32])
	digest := h.Sum(nil)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A extendedGroupElement
	geScalarMultBase(&A, digest[:32])
	A.ToBytes(secretKey[32:])
	return secretKey, PublicKey(secretKey[32:])
}

// Sign signs the message with secretKey and returns a signature.
func Sign(sk SecretKey, message []byte) Signature {
	h := sha512.New()
	h.Write(sk[:32])

	digest := h.Sum(nil)
	digest[0] &= 248
	digest[31] &= 63
	digest[31] |= 64

	h.Reset()
	h.Write(digest[32:])
	h.Write(message)
	messageDigest := h.Sum(nil)

	var messageDigestReduced [32]byte
	scReduce(messageDigestReduced[:], messageDigest)
	var R extendedGroupElement
	geScalarMultBase(&R, messageDigestReduced[:])

	var hramDigestReduced [32]byte
	signature := make([]byte, 64)
	R.ToBytes(signature[:32])
	h.Reset()
	h.Write(signature[:32])
	h.Write(sk[32:])
	h.Write(message)
	hramDigest := h.Sum(nil)
	scReduce(hramDigestReduced[:], hramDigest)
	scMulAdd(signature[32:], hramDigestReduced[:], digest[:32], messageDigestReduced[:])
	return Signature(signature[:])
}

// Verify returns true iff sig is a valid signature of message by publicKey.
func Verify(pk PublicKey, message []byte, sig Signature) bool {
	if sig[63]&224 != 0 {
		return false
	}
	var A extendedGroupElement
	if !A.FromBytes(pk) {
		return false
	}

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(pk)
	h.Write(message)
	digest := h.Sum(nil)

	var hReduced [32]byte
	var R projectiveGroupElement
	scReduce(hReduced[:], digest[:])
	geDoubleScalarMultVartime(&R, hReduced[:], &A, sig[32:])

	var checkR [32]byte
	R.ToBytes(&checkR)
	return bytes.Equal(sig[:32], checkR[:])
}
