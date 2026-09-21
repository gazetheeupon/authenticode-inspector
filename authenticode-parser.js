/*
 * Parser for Authenticode (Microsoft Authenticode) digital signatures
 * embedded in Windows PE files (.exe, .dll, .sys, .cat is a different
 * container and is NOT handled here).
 *
 * Format background:
 *
 *   A signed PE file has an IMAGE_DIRECTORY_ENTRY_SECURITY entry (index 4
 *   of the 16 data directories in the Optional Header) whose "address" is
 *   unusually a plain FILE OFFSET (not an RVA, unlike every other data
 *   directory) pointing at a WIN_CERTIFICATE structure appended after the
 *   mapped image:
 *
 *     WIN_CERTIFICATE {
 *       DWORD dwLength;       // length of this structure, INCLUDING this
 *                              // header, EXCLUDING any 8-byte alignment
 *                              // padding appended after it
 *       WORD  wRevision;      // 0x0200 = WIN_CERT_REVISION_2_0
 *       WORD  wCertType;      // 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA
 *       BYTE  bCertificate[]; // a DER-encoded PKCS#7 ContentInfo of type
 *                              // signedData
 *     }
 *
 *   That PKCS#7 SignedData holds:
 *     - the signer's X.509 certificate chain (as embedded by signtool),
 *     - an encapsulated SpcIndirectDataContent (the Authenticode-specific
 *       structure) carrying the file's DECLARED hash and hash algorithm,
 *     - one SignerInfo, whose authenticated attributes carry the signing
 *       purpose, a program name / URL (SpcSpOpusInfo), and a message
 *       digest; and whose UNauthenticated attributes may carry a
 *       timestamp: either a legacy PKCS#9 countersignature (OID
 *       1.2.840.113549.1.9.6) or a modern RFC3161 timestamp token (OID
 *       1.3.6.1.4.1.311.3.3.1, a full nested ContentInfo/SignedData/TSTInfo).
 *
 *   The DECLARED hash inside SpcIndirectDataContent is computed over the
 *   file with a specific set of exclusions (see computeAuthenticodeHash
 *   below). Recomputing that hash independently and comparing it to the
 *   declared value tells you whether the signature still covers the
 *   file's current bytes -- i.e. whether the file has been modified since
 *   it was signed -- WITHOUT needing to validate the certificate chain's
 *   trust at all. That is the one thing this tool claims to check.
 *
 * Explicitly OUT OF SCOPE, on purpose:
 *   - Certificate chain / trust validation (is the signer's cert trusted
 *     by a root Windows trusts). We are not a substitute for
 *     `signtool verify` or the Windows Authenticode trust engine.
 *   - Any live revocation check (CRL/OCSP). We never claim one was done.
 *   - Verifying the cryptographic signature itself (that encryptedDigest
 *     really is a valid RSA/ECDSA signature over the authenticated
 *     attributes, produced by the signer's private key). We show what the
 *     signature *claims*; we don't re-derive trust in who made the claim.
 *
 * This file is a from-scratch minimal DER/BER (ASN.1) reader plus
 * structure-specific extraction for PKCS#7 SignedData, X.509 certificates,
 * SpcIndirectDataContent, SpcSpOpusInfo, and RFC3161 TSTInfo. No external
 * crypto/ASN.1 library is used for parsing. Digest recomputation uses the
 * standard Web Crypto API (crypto.subtle), available in both browsers and
 * modern Node, so this file works unmodified in the ground-truth Node test
 * suite and in the deployed page.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.AuthenticodeInspector = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class AuthenticodeParseError extends Error {}

  // ---------------------------------------------------------------------
  // Minimal DER/BER reader
  // ---------------------------------------------------------------------

  const CLASS_UNIVERSAL = 0;
  const CLASS_APPLICATION = 1;
  const CLASS_CONTEXT = 2;
  const CLASS_PRIVATE = 3;

  // Reads one TLV (tag-length-value) node starting at `pos` in `bytes`
  // (a Uint8Array). Returns { class, constructed, tagNumber, tagByte,
  // headerLen, contentStart, contentEnd, end }, where `end` is the byte
  // offset immediately after this node (contentEnd + any indefinite-length
  // terminator, though DER should never use indefinite length).
  function readNode(bytes, pos, limit) {
    limit = limit === undefined ? bytes.length : limit;
    if (pos >= limit) throw new AuthenticodeParseError('Unexpected end of DER data while reading a tag');
    const tagByte = bytes[pos];
    const tagClass = (tagByte >> 6) & 0x03;
    const constructed = (tagByte & 0x20) !== 0;
    let tagNumber = tagByte & 0x1f;
    let p = pos + 1;
    if (tagNumber === 0x1f) {
      // High-tag-number form (base-128). Not used by anything we parse,
      // but handle it rather than silently misreading.
      tagNumber = 0;
      let b;
      do {
        if (p >= limit) throw new AuthenticodeParseError('Truncated high tag number');
        b = bytes[p++];
        tagNumber = (tagNumber << 7) | (b & 0x7f);
      } while (b & 0x80);
    }
    if (p >= limit) throw new AuthenticodeParseError('Truncated DER length');
    const lenByte = bytes[p++];
    let length;
    if ((lenByte & 0x80) === 0) {
      length = lenByte;
    } else {
      const numLenBytes = lenByte & 0x7f;
      if (numLenBytes === 0) {
        throw new AuthenticodeParseError('Indefinite-length DER encoding is not supported');
      }
      if (numLenBytes > 6) throw new AuthenticodeParseError('DER length field implausibly large');
      length = 0;
      for (let i = 0; i < numLenBytes; i++) {
        if (p >= limit) throw new AuthenticodeParseError('Truncated DER length');
        length = length * 256 + bytes[p++];
      }
    }
    const contentStart = p;
    const contentEnd = contentStart + length;
    if (contentEnd > limit) throw new AuthenticodeParseError('DER node length runs past the end of its container');
    return {
      class: tagClass,
      constructed,
      tagNumber,
      tagByte,
      start: pos,
      headerLen: contentStart - pos,
      contentStart,
      contentEnd,
      end: contentEnd,
    };
  }

  // The complete TLV encoding of a node (tag + length + content), as
  // opposed to nodeBytes() which returns only the content.
  function fullNodeBytes(bytes, node) {
    return bytes.subarray(node.start, node.contentEnd);
  }

  // Walks the immediate children of a constructed node's content region.
  function children(bytes, node) {
    const out = [];
    let p = node.contentStart;
    while (p < node.contentEnd) {
      const child = readNode(bytes, p, node.contentEnd);
      out.push(child);
      p = child.end;
    }
    return out;
  }

  function topLevelNodes(bytes) {
    const out = [];
    let p = 0;
    while (p < bytes.length) {
      const node = readNode(bytes, p, bytes.length);
      out.push(node);
      p = node.end;
    }
    return out;
  }

  function nodeBytes(bytes, node) {
    return bytes.subarray(node.contentStart, node.contentEnd);
  }

  function isUniversal(node, tagNumber) {
    return node.class === CLASS_UNIVERSAL && node.tagNumber === tagNumber;
  }

  function isContext(node, tagNumber) {
    return node.class === CLASS_CONTEXT && node.tagNumber === tagNumber;
  }

  const TAG = {
    INTEGER: 2,
    BIT_STRING: 3,
    OCTET_STRING: 4,
    NULL: 5,
    OID: 6,
    UTF8String: 12,
    SEQUENCE: 16,
    SET: 17,
    PrintableString: 19,
    T61String: 20,
    IA5String: 22,
    UTCTime: 23,
    GeneralizedTime: 24,
    BMPString: 30,
  };

  function oidToDotted(bytes, node) {
    const b = nodeBytes(bytes, node);
    if (!b.length) return '';
    const parts = [];
    const first = b[0];
    parts.push(Math.floor(first / 40), first % 40);
    let value = 0;
    for (let i = 1; i < b.length; i++) {
      value = value * 128 + (b[i] & 0x7f);
      if ((b[i] & 0x80) === 0) {
        parts.push(value);
        value = 0;
      }
    }
    return parts.join('.');
  }

  function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
  }

  // Reads a DER INTEGER as an unsigned hex string (serial numbers, which
  // routinely exceed 2^53 and must not go through Number).
  function integerToHex(bytes, node) {
    let b = nodeBytes(bytes, node);
    // Drop a leading 0x00 sign-disambiguation byte if present (and it's
    // not the only byte), matching how serials are conventionally shown.
    if (b.length > 1 && b[0] === 0x00) b = b.subarray(1);
    return bytesToHex(b).toUpperCase();
  }

  function utf8FromLatin1Ish(bytes) {
    // T61String / PrintableString / IA5String: treat as Latin-1/ASCII,
    // which covers everything real-world certs and signtool actually emit.
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }

  function decodeDirectoryString(bytes, node) {
    const raw = nodeBytes(bytes, node);
    if (isUniversal(node, TAG.UTF8String)) {
      return new TextDecoder('utf-8').decode(raw);
    }
    if (isUniversal(node, TAG.BMPString)) {
      // UCS-2BE
      let s = '';
      for (let i = 0; i + 1 < raw.length; i += 2) s += String.fromCharCode((raw[i] << 8) | raw[i + 1]);
      return s;
    }
    return utf8FromLatin1Ish(raw);
  }

  function parseTime(bytes, node) {
    const s = utf8FromLatin1Ish(nodeBytes(bytes, node));
    // UTCTime: YYMMDDHHMM[SS]Z   GeneralizedTime: YYYYMMDDHHMM[SS][.f]Z
    let m;
    if (isUniversal(node, TAG.UTCTime)) {
      m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s);
      if (!m) return { raw: s, iso: null };
      let year = parseInt(m[1], 10);
      year += year < 50 ? 2000 : 1900;
      const iso = `${year}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] || '00'}Z`;
      return { raw: s, iso };
    }
    if (isUniversal(node, TAG.GeneralizedTime)) {
      m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.(\d+))?Z$/.exec(s);
      if (!m) return { raw: s, iso: null };
      const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] || '00'}${m[7] ? '.' + m[7] : ''}Z`;
      return { raw: s, iso };
    }
    return { raw: s, iso: null };
  }

  // ---------------------------------------------------------------------
  // Well-known OIDs
  // ---------------------------------------------------------------------

  const OID = {
    // PKCS#7 / CMS content types
    PKCS7_DATA: '1.2.840.113549.1.7.1',
    PKCS7_SIGNED_DATA: '1.2.840.113549.1.7.2',
    // PKCS#9 attributes
    CONTENT_TYPE: '1.2.840.113549.1.9.3',
    MESSAGE_DIGEST: '1.2.840.113549.1.9.4',
    SIGNING_TIME: '1.2.840.113549.1.9.5',
    COUNTER_SIGNATURE: '1.2.840.113549.1.9.6',
    // Authenticode / SPC (Microsoft "Software Publisher Certificate") OIDs
    SPC_INDIRECT_DATA_OBJID: '1.3.6.1.4.1.311.2.1.4',
    SPC_SP_OPUS_INFO_OBJID: '1.3.6.1.4.1.311.2.1.12',
    SPC_STATEMENT_TYPE_OBJID: '1.3.6.1.4.1.311.2.1.11',
    SPC_PE_IMAGE_DATA_OBJID: '1.3.6.1.4.1.311.2.1.15',
    SPC_INDIVIDUAL_SP_KEY_PURPOSE: '1.3.6.1.4.1.311.2.1.21',
    SPC_COMMERCIAL_SP_KEY_PURPOSE: '1.3.6.1.4.1.311.2.1.22',
    SPC_RFC3161_OBJID: '1.3.6.1.4.1.311.3.3.1',
    // RFC3161 TSTInfo content type
    TSTINFO: '1.2.840.113549.1.9.16.1.4',
    // Digest algorithms
    SHA1: '1.3.14.3.2.26',
    SHA256: '2.16.840.1.101.3.4.2.1',
    SHA384: '2.16.840.1.101.3.4.2.2',
    SHA512: '2.16.840.1.101.3.4.2.3',
    MD5: '1.2.840.113549.2.5',
    // X.500 attribute types (for Name/RDN)
    CN: '2.5.4.3',
    O: '2.5.4.10',
    OU: '2.5.4.11',
    L: '2.5.4.7',
    ST: '2.5.4.8',
    C: '2.5.4.6',
    EMAIL: '1.2.840.113549.1.9.1',
  };

  const DIGEST_ALGO_NAMES = {
    [OID.SHA1]: 'SHA-1',
    [OID.SHA256]: 'SHA-256',
    [OID.SHA384]: 'SHA-384',
    [OID.SHA512]: 'SHA-512',
    [OID.MD5]: 'MD5',
  };

  // Maps our friendly digest algorithm name to what crypto.subtle.digest expects.
  const SUBTLE_DIGEST_NAME = {
    'SHA-1': 'SHA-1',
    'SHA-256': 'SHA-256',
    'SHA-384': 'SHA-384',
    'SHA-512': 'SHA-512',
  };

  const RDN_LABELS = {
    [OID.CN]: 'CN',
    [OID.O]: 'O',
    [OID.OU]: 'OU',
    [OID.L]: 'L',
    [OID.ST]: 'ST',
    [OID.C]: 'C',
    [OID.EMAIL]: 'emailAddress',
  };

  // ---------------------------------------------------------------------
  // X.501 Name (issuer / subject)
  // ---------------------------------------------------------------------

  // nameNode is a SEQUENCE OF SET OF AttributeTypeAndValue (an RDNSequence).
  function parseName(bytes, nameNode) {
    const attrs = [];
    for (const rdn of children(bytes, nameNode)) {
      // rdn is a SET OF AttributeTypeAndValue; in practice almost always
      // exactly one, but walk all of them to be safe.
      for (const atv of children(bytes, rdn)) {
        const [typeNode, valueNode] = children(bytes, atv);
        if (!typeNode || !valueNode) continue;
        const oid = oidToDotted(bytes, typeNode);
        const value = decodeDirectoryString(bytes, valueNode);
        attrs.push({ oid, label: RDN_LABELS[oid] || oid, value });
      }
    }
    const byLabel = {};
    for (const a of attrs) if (!(a.label in byLabel)) byLabel[a.label] = a.value;
    const distinguishedName = attrs.map((a) => `${a.label}=${a.value}`).join(', ');
    return { attrs, ...byLabel, distinguishedName };
  }

  // ---------------------------------------------------------------------
  // X.509 Certificate (just enough: subject, issuer, serial, validity)
  // ---------------------------------------------------------------------

  function parseCertificate(bytes, certNode) {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    const [tbs] = children(bytes, certNode);
    const tbsChildren = children(bytes, tbs);
    let i = 0;
    // version [0] EXPLICIT INTEGER DEFAULT v1 -- optional
    let version = 1;
    if (isContext(tbsChildren[i], 0)) {
      const inner = children(bytes, tbsChildren[i])[0];
      version = 1 + parseInt(bytesToHex(nodeBytes(bytes, inner)) || '0', 16);
      i++;
    }
    const serialNode = tbsChildren[i++];
    const serialHex = integerToHex(bytes, serialNode);
    i++; // signature AlgorithmIdentifier (inside TBS) -- skip
    const issuerNode = tbsChildren[i++];
    const validityNode = tbsChildren[i++];
    const subjectNode = tbsChildren[i++];
    const issuer = parseName(bytes, issuerNode);
    const subject = parseName(bytes, subjectNode);
    const [notBeforeNode, notAfterNode] = children(bytes, validityNode);
    const notBefore = parseTime(bytes, notBeforeNode);
    const notAfter = parseTime(bytes, notAfterNode);
    return { version, serialHex, issuer, subject, notBefore, notAfter };
  }

  // ---------------------------------------------------------------------
  // SpcSpOpusInfo (program name + "more info" URL shown by signtool /d /du)
  // ---------------------------------------------------------------------

  function parseSpcSpOpusInfo(bytes, seqNode) {
    let programName = null;
    let moreInfoUrl = null;
    for (const field of children(bytes, seqNode)) {
      if (isContext(field, 0)) {
        // [0] EXPLICIT SpcString  (CHOICE: [0] unicode BMPString IMPLICIT, [1] ascii IA5String IMPLICIT)
        const inner = children(bytes, field)[0];
        if (inner) {
          if (isContext(inner, 0)) {
            const raw = nodeBytes(bytes, inner);
            let s = '';
            for (let k = 0; k + 1 < raw.length; k += 2) s += String.fromCharCode((raw[k] << 8) | raw[k + 1]);
            programName = s;
          } else if (isContext(inner, 1)) {
            programName = utf8FromLatin1Ish(nodeBytes(bytes, inner));
          }
        }
      } else if (isContext(field, 1)) {
        // [1] EXPLICIT SpcLink (CHOICE: [0] url IA5String IMPLICIT, ...)
        const inner = children(bytes, field)[0];
        if (inner && isContext(inner, 0)) {
          moreInfoUrl = utf8FromLatin1Ish(nodeBytes(bytes, inner));
        }
      }
    }
    return { programName, moreInfoUrl };
  }

  // ---------------------------------------------------------------------
  // Attributes (authenticated / unauthenticated)
  // ---------------------------------------------------------------------

  // attrSetNode's children are Attribute ::= SEQUENCE { type OID, values SET OF ANY }
  function parseAttributes(bytes, attrSetNode) {
    const out = [];
    for (const attr of children(bytes, attrSetNode)) {
      const [typeNode, valuesNode] = children(bytes, attr);
      if (!typeNode || !valuesNode) continue;
      const oid = oidToDotted(bytes, typeNode);
      const values = children(bytes, valuesNode);
      out.push({ oid, valuesNode, values });
    }
    return out;
  }

  function findAttr(attrs, oid) {
    return attrs.find((a) => a.oid === oid);
  }

  // ---------------------------------------------------------------------
  // RFC3161 TSTInfo (embedded inside an RFC3161 unauthenticated attribute)
  // ---------------------------------------------------------------------

  function parseGeneralNameDirectoryName(bytes, tsaFieldNode) {
    // tsaFieldNode is [0] EXPLICIT GeneralName. GeneralName is a CHOICE;
    // we only care about the directoryName [4] EXPLICIT Name choice, which
    // is what real-world TSAs (and our own fixture) emit.
    const generalName = children(bytes, tsaFieldNode)[0];
    if (!generalName) return null;
    if (isContext(generalName, 4)) {
      const nameSeq = children(bytes, generalName)[0];
      if (nameSeq) return parseName(bytes, nameSeq);
    }
    return null;
  }

  function parseTSTInfo(bytes, tstInfoSeq) {
    const parts = children(bytes, tstInfoSeq);
    let i = 0;
    i++; // version INTEGER
    const policyNode = parts[i++];
    const policyOid = oidToDotted(bytes, policyNode);
    i++; // messageImprint SEQUENCE -- the digest of the *original TSA query data*, not the PE file; skip
    const serialNode = parts[i++];
    const serialHex = integerToHex(bytes, serialNode);
    const genTimeNode = parts[i++];
    const genTime = parseTime(bytes, genTimeNode);
    let tsaName = null;
    for (; i < parts.length; i++) {
      const p = parts[i];
      if (isContext(p, 0)) {
        tsaName = parseGeneralNameDirectoryName(bytes, p);
      }
    }
    return { policyOid, serialHex, genTime, tsaName };
  }

  // A full RFC3161 timestamp token is itself a PKCS#7/CMS ContentInfo of
  // type signedData, whose encapsulated content (eContentType = TSTINFO)
  // is the TSTInfo above. We reuse parseSignedData (defined below) for the
  // outer envelope, then also expose the TSA's own certificate (usually
  // exactly one, embedded by the TSA) for display -- not for trust.
  function parseRfc3161Token(bytes, contentInfoNode) {
    const signedData = parseSignedDataContentInfo(bytes, contentInfoNode);
    const tstInfoBytes = signedData.encapContent.eContentBytes;
    if (!tstInfoBytes) throw new AuthenticodeParseError('RFC3161 token has no encapsulated TSTInfo content');
    const tstInfoTopNode = readNode(tstInfoBytes, 0);
    const tstInfo = parseTSTInfo(tstInfoBytes, tstInfoTopNode);
    return {
      ...tstInfo,
      tsaCertificates: signedData.certificates,
    };
  }

  // ---------------------------------------------------------------------
  // SpcIndirectDataContent (the Authenticode-specific "what got hashed")
  // ---------------------------------------------------------------------

  function parseSpcIndirectDataContent(bytes, seqNode) {
    const [, digestInfoNode] = children(bytes, seqNode);
    // digestInfoNode: SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
    const [algIdNode, digestNode] = children(bytes, digestInfoNode);
    const algOidNode = children(bytes, algIdNode)[0];
    const algOid = oidToDotted(bytes, algOidNode);
    const digestHex = bytesToHex(nodeBytes(bytes, digestNode)).toUpperCase();
    return {
      digestAlgorithmOid: algOid,
      digestAlgorithm: DIGEST_ALGO_NAMES[algOid] || algOid,
      digestHex,
    };
  }

  // ---------------------------------------------------------------------
  // SignerInfo
  // ---------------------------------------------------------------------

  function parseSignerInfo(bytes, siNode) {
    const parts = children(bytes, siNode);
    let i = 0;
    i++; // version
    const iasNode = parts[i++]; // issuerAndSerialNumber SEQUENCE { issuer Name, serialNumber INTEGER }
    const [issuerNode, serialNode] = children(bytes, iasNode);
    const issuer = parseName(bytes, issuerNode);
    const serialHex = integerToHex(bytes, serialNode);
    const digestAlgIdNode = parts[i++];
    const digestAlgOid = oidToDotted(bytes, children(bytes, digestAlgIdNode)[0]);

    let authAttrsNode = null;
    if (parts[i] && isContext(parts[i], 0)) {
      authAttrsNode = parts[i];
      i++;
    }
    i++; // digestEncryptionAlgorithm (signature algorithm)
    i++; // encryptedDigest OCTET STRING (the actual signature bytes) -- not verified
    let unauthAttrsNode = null;
    if (parts[i] && isContext(parts[i], 1)) {
      unauthAttrsNode = parts[i];
      i++;
    }

    const authAttrs = authAttrsNode ? parseAttributes(bytes, authAttrsNode) : [];
    const unauthAttrs = unauthAttrsNode ? parseAttributes(bytes, unauthAttrsNode) : [];

    // Authenticated attributes we surface:
    let signingTimeClaimed = null;
    const signingTimeAttr = findAttr(authAttrs, OID.SIGNING_TIME);
    if (signingTimeAttr && signingTimeAttr.values[0]) {
      signingTimeClaimed = parseTime(bytes, signingTimeAttr.values[0]);
    }

    let messageDigestFromAuthAttrs = null;
    const mdAttr = findAttr(authAttrs, OID.MESSAGE_DIGEST);
    if (mdAttr && mdAttr.values[0]) {
      messageDigestFromAuthAttrs = bytesToHex(nodeBytes(bytes, mdAttr.values[0])).toUpperCase();
    }

    let programName = null;
    let moreInfoUrl = null;
    const opusAttr = findAttr(authAttrs, OID.SPC_SP_OPUS_INFO_OBJID);
    if (opusAttr && opusAttr.values[0]) {
      const info = parseSpcSpOpusInfo(bytes, opusAttr.values[0]);
      programName = info.programName;
      moreInfoUrl = info.moreInfoUrl;
    }

    let statementType = null;
    const stmtAttr = findAttr(authAttrs, OID.SPC_STATEMENT_TYPE_OBJID);
    if (stmtAttr && stmtAttr.values[0]) {
      const oidNode = children(bytes, stmtAttr.values[0])[0];
      if (oidNode) {
        const oid = oidToDotted(bytes, oidNode);
        statementType =
          oid === OID.SPC_INDIVIDUAL_SP_KEY_PURPOSE
            ? 'Individual code signing'
            : oid === OID.SPC_COMMERCIAL_SP_KEY_PURPOSE
            ? 'Commercial code signing'
            : oid;
      }
    }

    // Unauthenticated attributes: timestamp, one of two schemes.
    let timestamp = null;
    const rfc3161Attr = findAttr(unauthAttrs, OID.SPC_RFC3161_OBJID);
    const legacyCsAttr = findAttr(unauthAttrs, OID.COUNTER_SIGNATURE);
    if (rfc3161Attr && rfc3161Attr.values[0]) {
      try {
        const token = parseRfc3161Token(bytes, rfc3161Attr.values[0]);
        timestamp = {
          scheme: 'rfc3161',
          time: token.genTime,
          tsaName: token.tsaName,
          tsaCertificates: token.tsaCertificates,
          serialHex: token.serialHex,
          policyOid: token.policyOid,
        };
      } catch (e) {
        timestamp = { scheme: 'rfc3161', error: `Could not parse the RFC3161 timestamp token: ${e.message}` };
      }
    } else if (legacyCsAttr && legacyCsAttr.values[0]) {
      try {
        const cs = parseSignerInfo(bytes, legacyCsAttr.values[0]);
        timestamp = {
          scheme: 'legacy-countersignature',
          time: cs.signingTimeClaimed,
          issuer: cs.issuer,
          serialHex: cs.serialHex,
        };
      } catch (e) {
        timestamp = { scheme: 'legacy-countersignature', error: `Could not parse the legacy countersignature: ${e.message}` };
      }
    }

    return {
      issuer,
      serialHex,
      digestAlgorithm: DIGEST_ALGO_NAMES[digestAlgOid] || digestAlgOid,
      signingTimeClaimed,
      messageDigestFromAuthAttrs,
      programName,
      moreInfoUrl,
      statementType,
      timestamp,
      hasAuthenticatedAttributes: !!authAttrsNode,
    };
  }

  // ---------------------------------------------------------------------
  // SignedData / ContentInfo
  // ---------------------------------------------------------------------

  // contentInfoNode: SEQUENCE { contentType OID, [0] EXPLICIT content ANY OPTIONAL }
  // Returns the parsed inner value plus raw bytes of the encapsulated content
  // (useful both for the outer PKCS#7 SignedData, and for the inner
  // encapContentInfo whose content is the SpcIndirectDataContent / TSTInfo).
  function parseSignedDataContentInfo(bytes, contentInfoNode) {
    const [contentTypeNode, explicitWrapper] = children(bytes, contentInfoNode);
    const contentType = oidToDotted(bytes, contentTypeNode);
    if (contentType !== OID.PKCS7_SIGNED_DATA) {
      throw new AuthenticodeParseError(`Expected a PKCS#7 SignedData (OID ${OID.PKCS7_SIGNED_DATA}), found ${contentType}`);
    }
    if (!explicitWrapper) throw new AuthenticodeParseError('PKCS#7 ContentInfo has no content');
    const signedDataSeq = children(bytes, explicitWrapper)[0];
    const sdParts = children(bytes, signedDataSeq);
    let i = 0;
    i++; // version
    i++; // digestAlgorithms SET
    const encapContentInfoNode = sdParts[i++];
    const [eContentTypeNode, eContentWrapper] = children(bytes, encapContentInfoNode);
    const eContentType = oidToDotted(bytes, eContentTypeNode);
    // encapContentInfo's content field is declared `[0] EXPLICIT ANY` in
    // classic PKCS#7 (which is what Authenticode actually uses, not modern
    // CMS's stricter `[0] EXPLICIT OCTET STRING`). In practice this shows
    // up two different ways: some encoders wrap the real DER value in an
    // OCTET STRING as CMS would, others (osslsigncode among them) embed
    // the value's own TLV directly with no OCTET STRING at all. Handle
    // both: unwrap one OCTET STRING layer if present, otherwise treat the
    // wrapped child's own complete TLV bytes as the value to parse.
    let eContentBytes = null;
    if (eContentWrapper) {
      const wrapped = children(bytes, eContentWrapper)[0];
      if (wrapped) {
        eContentBytes = isUniversal(wrapped, TAG.OCTET_STRING) ? nodeBytes(bytes, wrapped) : fullNodeBytes(bytes, wrapped);
      }
    }

    const certificates = [];
    let signerInfosNode = null;
    for (; i < sdParts.length; i++) {
      const p = sdParts[i];
      if (isContext(p, 0)) {
        // [0] IMPLICIT SET OF Certificate
        for (const certNode of children(bytes, p)) {
          try {
            certificates.push(parseCertificate(bytes, certNode));
          } catch (e) {
            // Don't let one malformed/extension cert abort the whole parse.
            certificates.push({ error: `Could not parse an embedded certificate: ${e.message}` });
          }
        }
      } else if (isContext(p, 1)) {
        // [1] IMPLICIT SET OF CRL -- not used by Authenticode, ignore.
      } else if (isUniversal(p, TAG.SET)) {
        signerInfosNode = p;
      }
    }

    const signerInfos = signerInfosNode ? children(bytes, signerInfosNode).map((si) => parseSignerInfo(bytes, si)) : [];

    return {
      eContentType,
      encapContent: { eContentType, eContentBytes },
      certificates,
      signerInfos,
    };
  }

  // ---------------------------------------------------------------------
  // Top-level: WIN_CERTIFICATE -> Authenticode-specific SignedData
  // ---------------------------------------------------------------------

  function parseWinCertificateBlob(bytes) {
    // bytes here is the PKCS#7 ContentInfo DER (the bCertificate[] field).
    // Some signing tools (osslsigncode among them) round bCertificate's
    // own length up to an 8-byte boundary with trailing zero padding
    // *inside* the WIN_CERTIFICATE's dwLength, rather than strictly after
    // it as the spec describes -- so read exactly one top-level DER value
    // from the start of the blob and ignore anything trailing it, rather
    // than requiring the whole buffer to be consumed.
    const contentInfoNode = readNode(bytes, 0);
    const sd = parseSignedDataContentInfo(bytes, contentInfoNode);
    if (sd.eContentType !== OID.SPC_INDIRECT_DATA_OBJID) {
      throw new AuthenticodeParseError(
        `This PKCS#7 SignedData does not carry Authenticode SpcIndirectDataContent (unexpected inner content type ${sd.eContentType})`
      );
    }
    if (!sd.encapContent.eContentBytes) throw new AuthenticodeParseError('SpcIndirectDataContent is missing');
    const spcTopNode = readNode(sd.encapContent.eContentBytes, 0);
    const spc = parseSpcIndirectDataContent(sd.encapContent.eContentBytes, spcTopNode);

    if (!sd.signerInfos.length) throw new AuthenticodeParseError('No SignerInfo found in the signature');
    const signer = sd.signerInfos[0];

    // Identify which embedded certificate is the signer's own leaf cert
    // (matched by issuer + serial, which is exactly what SignerInfo's
    // issuerAndSerialNumber is for).
    const certificates = sd.certificates.map((c) => ({
      ...c,
      isSigner: !c.error && c.issuer.distinguishedName === signer.issuer.distinguishedName && c.serialHex === signer.serialHex,
    }));

    return {
      declaredDigestAlgorithm: spc.digestAlgorithm,
      declaredDigestAlgorithmOid: spc.digestAlgorithmOid,
      declaredDigestHex: spc.digestHex,
      certificates,
      signer,
      allSignerInfos: sd.signerInfos,
    };
  }

  // ---------------------------------------------------------------------
  // PE header walking
  // ---------------------------------------------------------------------

  const IMAGE_DIRECTORY_ENTRY_SECURITY = 4;

  function readPEOffsets(view) {
    if (view.byteLength < 0x40) throw new AuthenticodeParseError('File is too small to be a PE image');
    if (view.getUint8(0) !== 0x4d || view.getUint8(1) !== 0x5a) {
      throw new AuthenticodeParseError('Not a PE file: missing "MZ" DOS header signature');
    }
    const e_lfanew = view.getUint32(0x3c, true);
    if (e_lfanew + 24 > view.byteLength) throw new AuthenticodeParseError('Not a PE file: e_lfanew points past the end of the file');
    if (view.getUint8(e_lfanew) !== 0x50 || view.getUint8(e_lfanew + 1) !== 0x45 || view.getUint8(e_lfanew + 2) !== 0 || view.getUint8(e_lfanew + 3) !== 0) {
      throw new AuthenticodeParseError('Not a PE file: missing "PE\\0\\0" signature');
    }
    const coffOff = e_lfanew + 4;
    const sizeOfOptionalHeader = view.getUint16(coffOff + 16, true);
    const optHdrOff = coffOff + 20;
    if (sizeOfOptionalHeader < 2) throw new AuthenticodeParseError('PE file has no Optional Header');
    const magic = view.getUint16(optHdrOff, true);
    let architecture;
    if (magic === 0x10b) architecture = 'PE32';
    else if (magic === 0x20b) architecture = 'PE32+';
    else throw new AuthenticodeParseError(`Unrecognized Optional Header magic 0x${magic.toString(16)}`);

    // The CheckSum field sits at optional-header-relative offset 64 in
    // BOTH PE32 and PE32+ (the fields before it differ in size -- PE32+'s
    // 8-byte ImageBase in place of PE32's 4-byte BaseOfData+ImageBase --
    // but they sum to the same 40 bytes either way).
    const checksumOff = optHdrOff + 64;

    // NumberOfRvaAndSizes sits right before the DataDirectory array; its
    // offset differs by architecture because of the differently-sized
    // stack/heap reserve/commit fields between CheckSum and it.
    const numRvaOff = architecture === 'PE32+' ? optHdrOff + 108 : optHdrOff + 92;
    const numRvaAndSizes = view.getUint32(numRvaOff, true);
    const dataDirOff = numRvaOff + 4;
    if (numRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
      return { architecture, checksumOff, hasSecurityDirectory: false };
    }
    const secDirEntryOff = dataDirOff + 8 * IMAGE_DIRECTORY_ENTRY_SECURITY;
    if (secDirEntryOff + 8 > view.byteLength) throw new AuthenticodeParseError('Data directory array runs past the end of the file');
    const secTableOffset = view.getUint32(secDirEntryOff, true); // a FILE offset, not an RVA, for this one directory entry
    const secTableSize = view.getUint32(secDirEntryOff + 4, true);
    return {
      architecture,
      checksumOff,
      secDirEntryOff,
      hasSecurityDirectory: secTableSize > 0,
      secTableOffset,
      secTableSize,
    };
  }

  // Recomputes the Authenticode PE hash: the whole file, hashed EXCLUDING
  // (a) the 4-byte CheckSum field, (b) the IMAGE_DIRECTORY_ENTRY_SECURITY
  // data directory entry itself (8 bytes: file offset + size, which
  // necessarily changes if the certificate table's size changes), and
  // (c) the appended certificate table (WIN_CERTIFICATE bytes) itself.
  // Returns a hex digest, using whatever algorithm the signature declared.
  async function computeAuthenticodeHash(buffer, offsets, algoName) {
    const subtleName = SUBTLE_DIGEST_NAME[algoName];
    if (!subtleName) throw new AuthenticodeParseError(`Unsupported digest algorithm for recomputation: ${algoName}`);
    const bytes = new Uint8Array(buffer);
    const chunks = [];
    let cursor = 0;

    function take(end) {
      if (end > cursor) {
        chunks.push(bytes.subarray(cursor, end));
        cursor = end;
      }
    }

    take(offsets.checksumOff);
    cursor = offsets.checksumOff + 4; // skip CheckSum

    if (offsets.hasSecurityDirectory !== undefined && offsets.secDirEntryOff !== undefined) {
      take(offsets.secDirEntryOff);
      cursor = offsets.secDirEntryOff + 8; // skip the security data directory entry
    }

    if (offsets.hasSecurityDirectory) {
      take(offsets.secTableOffset);
      cursor = offsets.secTableOffset + offsets.secTableSize; // skip the appended certificate table
    } else {
      // Nothing signed -- hash to EOF (this branch is only reached if a
      // caller asks to hash an unsigned file, which parsePEFile doesn't do).
    }

    take(bytes.length);

    const total = chunks.reduce((n, c) => n + c.length, 0);
    const combined = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) {
      combined.set(c, o);
      o += c.length;
    }
    const digest = await crypto.subtle.digest(subtleName, combined);
    return bytesToHex(new Uint8Array(digest)).toUpperCase();
  }

  // ---------------------------------------------------------------------
  // Public entry point
  // ---------------------------------------------------------------------

  // Parses structure only (synchronous, no hashing). Use
  // verifyDigest() afterwards to recompute + compare the file hash.
  function parsePEFile(buffer) {
    const view = new DataView(buffer);
    const offsets = readPEOffsets(view);
    const result = {
      architecture: offsets.architecture,
      fileSize: buffer.byteLength,
      signed: false,
      certificateBlobs: [],
      warnings: [],
    };

    if (!offsets.hasSecurityDirectory) {
      return { ...result, _offsets: offsets };
    }

    const bytes = new Uint8Array(buffer);
    let p = offsets.secTableOffset;
    const end = offsets.secTableOffset + offsets.secTableSize;
    if (end > bytes.length) throw new AuthenticodeParseError('Certificate table extends past the end of the file');

    while (p < end) {
      if (p + 8 > end) {
        result.warnings.push('Trailing bytes in the certificate table are too short for a WIN_CERTIFICATE header; ignored.');
        break;
      }
      const dv = new DataView(buffer, p, 8);
      const dwLength = dv.getUint32(0, true);
      const wRevision = dv.getUint16(4, true);
      const wCertType = dv.getUint16(6, true);
      if (dwLength < 8 || p + dwLength > end) {
        result.warnings.push('A WIN_CERTIFICATE entry has an invalid length; stopped reading the certificate table.');
        break;
      }
      const blobBytes = bytes.subarray(p + 8, p + dwLength);
      const entry = { wRevision, wCertType, offset: p, length: dwLength };
      if (wCertType !== 0x0002) {
        entry.warning = `Certificate entry type 0x${wCertType.toString(16)} is not WIN_CERT_TYPE_PKCS_SIGNED_DATA; not parsed.`;
      } else {
        try {
          entry.signedData = parseWinCertificateBlob(blobBytes);
        } catch (e) {
          entry.error = e.message;
        }
      }
      result.certificateBlobs.push(entry);
      // Entries are 8-byte aligned; dwLength itself excludes that padding.
      p += dwLength;
      p = Math.ceil(p / 8) * 8;
    }

    result.signed = result.certificateBlobs.some((b) => b.signedData);
    return { ...result, _offsets: offsets };
  }

  // Recomputes the Authenticode hash for the primary (first) signature and
  // reports whether it matches the declared hash -- i.e. whether the file
  // has been modified since it was signed. Async (uses crypto.subtle).
  async function verifyDigest(buffer, parsed) {
    const primary = parsed.certificateBlobs.find((b) => b.signedData);
    if (!primary) return null;
    const computedHex = await computeAuthenticodeHash(buffer, parsed._offsets, primary.signedData.declaredDigestAlgorithm);
    return {
      declaredHex: primary.signedData.declaredDigestHex,
      computedHex,
      matches: computedHex === primary.signedData.declaredDigestHex,
    };
  }

  return {
    AuthenticodeParseError,
    parsePEFile,
    verifyDigest,
    computeAuthenticodeHash,
    _internal: {
      readNode,
      children,
      topLevelNodes,
      nodeBytes,
      fullNodeBytes,
      isContext,
      isUniversal,
      oidToDotted,
      integerToHex,
      parseName,
      parseCertificate,
      parseSpcSpOpusInfo,
      parseAttributes,
      findAttr,
      parseTSTInfo,
      parseSignerInfo,
      parseSignedDataContentInfo,
      parseWinCertificateBlob,
      readPEOffsets,
      TAG,
      OID,
    },
  };
});
