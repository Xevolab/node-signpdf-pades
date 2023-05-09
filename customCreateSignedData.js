/**
 * This file is a modified version of a portion of the forge library.
 * The original file is located at:
 * https://github.com/digitalbazaar/forge/blob/a0a4a4264bedb3296974b9675349c9c190144aeb/lib/pkcs7.js
 * 
 * The original file is licensed under the BSD 3-Clause License.
 * 
	New BSD License (3-clause)
	Copyright (c) 2010, Digital Bazaar, Inc.
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
		* Redistributions of source code must retain the above copyright
			notice, this list of conditions and the following disclaimer.
		* Redistributions in binary form must reproduce the above copyright
			notice, this list of conditions and the following disclaimer in the
			documentation and/or other materials provided with the distribution.
		* Neither the name of Digital Bazaar, Inc. nor the
			names of its contributors may be used to endorse or promote products
			derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL DIGITAL BAZAAR BE LIABLE FOR ANY
	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

/**
 * This file modifies the behavior of the `_attributeToAsn1` function
 * called by `addSignerInfos` after the `sign` function is called.
 * This adds the ability to add custom signed attributes to the signed file
 * through the `authenticatedAttributes` array.
 * You can now define `authenticatedAttributes` as: [
 * 	{
			type: forge.pki.oids.contentType,
			value: forge.pki.oids.data,
		}, {
			type: forge.pki.oids.messageDigest,
			// value will be auto-populated at signing time
		},
		{
			type: '1.2.840.113549[...]',
			asn1Value: [forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
				...
			])]
		}
 * ]
 */

        import forge from 'node-forge';

        var asn1 = forge.asn1;
        var p7 = forge.pkcs7;
        
        export default function createSignedData() {
            var msg = null;
            msg = {
                type: forge.pki.oids.signedData,
                version: 1,
                certificates: [],
                crls: [],
                // TODO: add json-formatted signer stuff here?
                signers: [],
                // populated during sign()
                digestAlgorithmIdentifiers: [],
                contentInfo: null,
                signerInfos: [],
        
                fromAsn1: function (obj) {
                    // validate SignedData content block and capture data.
                    _fromAsn1(msg, obj, p7.asn1.signedDataValidator);
                    msg.certificates = [];
                    msg.crls = [];
                    msg.digestAlgorithmIdentifiers = [];
                    msg.contentInfo = null;
                    msg.signerInfos = [];
        
                    if (msg.rawCapture.certificates) {
                        var certs = msg.rawCapture.certificates.value;
                        for (var i = 0; i < certs.length; ++i) {
                            msg.certificates.push(forge.pki.certificateFromAsn1(certs[i]));
                        }
                    }
        
                    // TODO: parse crls
                },
        
                toAsn1: function () {
                    // degenerate case with no content
                    if (!msg.contentInfo) {
                        msg.sign();
                    }
        
                    var certs = [];
                    for (var i = 0; i < msg.certificates.length; ++i) {
                        certs.push(forge.pki.certificateToAsn1(msg.certificates[i]));
                    }
        
                    var crls = [];
                    // TODO: implement CRLs
        
                    // [0] SignedData
                    var signedData = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                            // Version
                            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
                                asn1.integerToDer(msg.version).getBytes()),
                            // DigestAlgorithmIdentifiers
                            asn1.create(
                                asn1.Class.UNIVERSAL, asn1.Type.SET, true,
                                msg.digestAlgorithmIdentifiers),
                            // ContentInfo
                            msg.contentInfo
                        ])
                    ]);
                    if (certs.length > 0) {
                        // [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL
                        signedData.value[0].value.push(
                            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, certs));
                    }
                    if (crls.length > 0) {
                        // [1] IMPLICIT CertificateRevocationLists OPTIONAL
                        signedData.value[0].value.push(
                            asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, crls));
                    }
                    // SignerInfos
                    signedData.value[0].value.push(
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true,
                            msg.signerInfos));
        
                    // ContentInfo
                    return asn1.create(
                        asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                        // ContentType
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                            asn1.oidToDer(msg.type).getBytes()),
                        // [0] SignedData
                        signedData
                    ]);
                },
        
                /**
                 * Add (another) entity to list of signers.
                 *
                 * Note: If authenticatedAttributes are provided, then, per RFC 2315,
                 * they must include at least two attributes: content type and
                 * message digest. The message digest attribute value will be
                 * auto-calculated during signing and will be ignored if provided.
                 *
                 * Here's an example of providing these two attributes:
                 *
                 * forge.pkcs7.createSignedData();
                 * p7.addSigner({
                 *   issuer: cert.issuer.attributes,
                 *   serialNumber: cert.serialNumber,
                 *   key: privateKey,
                 *   digestAlgorithm: forge.pki.oids.sha1,
                 *   authenticatedAttributes: [{
                 *     type: forge.pki.oids.contentType,
                 *     value: forge.pki.oids.data
                 *   }, {
                 *     type: forge.pki.oids.messageDigest
                 *   }]
                 * });
                 *
                 * TODO: Support [subjectKeyIdentifier] as signer's ID.
                 *
                 * @param signer the signer information:
                 *          key the signer's private key.
                 *          [certificate] a certificate containing the public key
                 *            associated with the signer's private key; use this option as
                 *            an alternative to specifying signer.issuer and
                 *            signer.serialNumber.
                 *          [issuer] the issuer attributes (eg: cert.issuer.attributes).
                 *          [serialNumber] the signer's certificate's serial number in
                 *           hexadecimal (eg: cert.serialNumber).
                 *          [digestAlgorithm] the message digest OID, as a string, to use
                 *            (eg: forge.pki.oids.sha1).
                 *          [authenticatedAttributes] an optional array of attributes
                 *            to also sign along with the content.
                 */
                addSigner: function (signer) {
                    var issuer = signer.issuer;
                    var serialNumber = signer.serialNumber;
                    if (signer.certificate) {
                        var cert = signer.certificate;
                        if (typeof cert === 'string') {
                            cert = forge.pki.certificateFromPem(cert);
                        }
                        issuer = cert.issuer.attributes;
                        serialNumber = cert.serialNumber;
                    }
                    var key = signer.key;
                    if (!key) {
                        throw new Error(
                            'Could not add PKCS#7 signer; no private key specified.');
                    }
                    if (typeof key === 'string') {
                        key = forge.pki.privateKeyFromPem(key);
                    }
        
                    // ensure OID known for digest algorithm
                    var digestAlgorithm = signer.digestAlgorithm || forge.pki.oids.sha1;
                    switch (digestAlgorithm) {
                        case forge.pki.oids.sha1:
                        case forge.pki.oids.sha256:
                        case forge.pki.oids.sha384:
                        case forge.pki.oids.sha512:
                        case forge.pki.oids.md5:
                            break;
                        default:
                            throw new Error(
                                'Could not add PKCS#7 signer; unknown message digest algorithm: ' +
                                digestAlgorithm);
                    }
        
                    // if authenticatedAttributes is present, then the attributes
                    // must contain at least PKCS #9 content-type and message-digest
                    var authenticatedAttributes = signer.authenticatedAttributes || [];
                    if (authenticatedAttributes.length > 0) {
                        var contentType = false;
                        var messageDigest = false;
                        for (var i = 0; i < authenticatedAttributes.length; ++i) {
                            var attr = authenticatedAttributes[i];
                            if (!contentType && attr.type === forge.pki.oids.contentType) {
                                contentType = true;
                                if (messageDigest) {
                                    break;
                                }
                                continue;
                            }
                            if (!messageDigest && attr.type === forge.pki.oids.messageDigest) {
                                messageDigest = true;
                                if (contentType) {
                                    break;
                                }
                                continue;
                            }
                        }
        
                        if (!contentType || !messageDigest) {
                            throw new Error('Invalid signer.authenticatedAttributes. If ' +
                                'signer.authenticatedAttributes is specified, then it must ' +
                                'contain at least two attributes, PKCS #9 content-type and ' +
                                'PKCS #9 message-digest.');
                        }
                    }
        
                    msg.signers.push({
                        key: key,
                        version: 1,
                        issuer: issuer,
                        serialNumber: serialNumber,
                        digestAlgorithm: digestAlgorithm,
                        signatureAlgorithm: forge.pki.oids.rsaEncryption,
                        signature: null,
                        authenticatedAttributes: authenticatedAttributes,
                        unauthenticatedAttributes: []
                    });
                },
        
                /**
                 * Signs the content.
                 * @param options Options to apply when signing:
                 *    [detached] boolean. If signing should be done in detached mode. Defaults to false.
                 */
                sign: function (options) {
                    options = options || {};
                    // auto-generate content info
                    if (typeof msg.content !== 'object' || msg.contentInfo === null) {
                        // use Data ContentInfo
                        msg.contentInfo = asn1.create(
                            asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                            // ContentType
                            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                                asn1.oidToDer(forge.pki.oids.data).getBytes())
                        ]);
        
                        // add actual content, if present
                        if ('content' in msg) {
                            var content;
                            if (msg.content instanceof forge.util.ByteBuffer) {
                                content = msg.content.bytes();
                            } else if (typeof msg.content === 'string') {
                                content = forge.util.encodeUtf8(msg.content);
                            }
        
                            if (options.detached) {
                                msg.detachedContent = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, content);
                            } else {
                                msg.contentInfo.value.push(
                                    // [0] EXPLICIT content
                                    asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
                                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                                            content)
                                    ]));
                            }
                        }
                    }
        
                    // no signers, return early (degenerate case for certificate container)
                    if (msg.signers.length === 0) {
                        return;
                    }
        
                    // generate digest algorithm identifiers
                    var mds = addDigestAlgorithmIds();
        
                    // generate signerInfos
                    addSignerInfos(mds);
                },
        
                verify: function () {
                    throw new Error('PKCS#7 signature verification not yet implemented.');
                },
        
                /**
                 * Add a certificate.
                 *
                 * @param cert the certificate to add.
                 */
                addCertificate: function (cert) {
                    // convert from PEM
                    if (typeof cert === 'string') {
                        cert = forge.pki.certificateFromPem(cert);
                    }
                    msg.certificates.push(cert);
                },
        
                /**
                 * Add a certificate revokation list.
                 *
                 * @param crl the certificate revokation list to add.
                 */
                addCertificateRevokationList: function (crl) {
                    throw new Error('PKCS#7 CRL support not yet implemented.');
                }
            };
            return msg;
        
            function addDigestAlgorithmIds() {
                var mds = {};
        
                for (var i = 0; i < msg.signers.length; ++i) {
                    var signer = msg.signers[i];
                    var oid = signer.digestAlgorithm;
                    if (!(oid in mds)) {
                        // content digest
                        mds[oid] = forge.md[forge.pki.oids[oid]].create();
                    }
                    if (signer.authenticatedAttributes.length === 0) {
                        // no custom attributes to digest; use content message digest
                        signer.md = mds[oid];
                    } else {
                        // custom attributes to be digested; use own message digest
                        // TODO: optimize to just copy message digest state if that
                        // feature is ever supported with message digests
                        signer.md = forge.md[forge.pki.oids[oid]].create();
                    }
                }
        
                // add unique digest algorithm identifiers
                msg.digestAlgorithmIdentifiers = [];
                for (var oid in mds) {
                    msg.digestAlgorithmIdentifiers.push(
                        // AlgorithmIdentifier
                        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                            // algorithm
                            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                                asn1.oidToDer(oid).getBytes()),
                            // parameters (null)
                            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
                        ]));
                }
        
                return mds;
            }
        
            function addSignerInfos(mds) {
                var content;
        
                if (msg.detachedContent) {
                    // Signature has been made in detached mode.
                    content = msg.detachedContent;
                } else {
                    // Note: ContentInfo is a SEQUENCE with 2 values, second value is
                    // the content field and is optional for a ContentInfo but required here
                    // since signers are present
                    // get ContentInfo content
                    content = msg.contentInfo.value[1];
                    // skip [0] EXPLICIT content wrapper
                    content = content.value[0];
                }
        
                if (!content) {
                    throw new Error(
                        'Could not sign PKCS#7 message; there is no content to sign.');
                }
        
                // get ContentInfo content type
                var contentType = asn1.derToOid(msg.contentInfo.value[0].value);
        
                // serialize content
                var bytes = asn1.toDer(content);
        
                // skip identifier and length per RFC 2315 9.3
                // skip identifier (1 byte)
                bytes.getByte();
                // read and discard length bytes
                asn1.getBerValueLength(bytes);
                bytes = bytes.getBytes();
        
                // digest content DER value bytes
                for (var oid in mds) {
                    mds[oid].start().update(bytes);
                }
        
                // sign content
                var signingTime = new Date();
                for (var i = 0; i < msg.signers.length; ++i) {
                    var signer = msg.signers[i];
        
                    if (signer.authenticatedAttributes.length === 0) {
                        // if ContentInfo content type is not "Data", then
                        // authenticatedAttributes must be present per RFC 2315
                        if (contentType !== forge.pki.oids.data) {
                            throw new Error(
                                'Invalid signer; authenticatedAttributes must be present ' +
                                'when the ContentInfo content type is not PKCS#7 Data.');
                        }
                    } else {
                        // process authenticated attributes
                        // [0] IMPLICIT
                        signer.authenticatedAttributesAsn1 = asn1.create(
                            asn1.Class.CONTEXT_SPECIFIC, 0, true, []);
        
                        // per RFC 2315, attributes are to be digested using a SET container
                        // not the above [0] IMPLICIT container
                        var attrsAsn1 = asn1.create(
                            asn1.Class.UNIVERSAL, asn1.Type.SET, true, []);
        
                        for (var ai = 0; ai < signer.authenticatedAttributes.length; ++ai) {
                            var attr = signer.authenticatedAttributes[ai];
                            if (attr.type === forge.pki.oids.messageDigest) {
                                // use content message digest as value
                                attr.value = mds[signer.digestAlgorithm].digest();
                            } else if (attr.type === forge.pki.oids.signingTime) {
                                // auto-populate signing time if not already set
                                if (!attr.value) {
                                    attr.value = signingTime;
                                }
                            }
        
                            // convert to ASN.1 and push onto Attributes SET (for signing) and
                            // onto authenticatedAttributesAsn1 to complete SignedData ASN.1
                            // TODO: optimize away duplication
                            attrsAsn1.value.push(_attributeToAsn1(attr));
                            console.log("Getting attribute ", attr, " which got transformed into ", _attributeToAsn1(attr));
                            signer.authenticatedAttributesAsn1.value.push(_attributeToAsn1(attr));
                        }
        
                        // DER-serialize and digest SET OF attributes only
                        bytes = asn1.toDer(attrsAsn1).getBytes();
                        signer.md.start().update(bytes);
                    }
        
                    // sign digest
                    signer.signature = signer.key.sign(signer.md, 'RSASSA-PKCS1-V1_5');
                }
        
                // add signer info
                msg.signerInfos = _signersToAsn1(msg.signers);
            }
        };
        
        
        function _fromAsn1(msg, obj, validator) {
            var capture = {};
            var errors = [];
            if (!asn1.validate(obj, validator, capture, errors)) {
                var error = new Error('Cannot read PKCS#7 message. ' +
                    'ASN.1 object is not a supported PKCS#7 message.');
                error.errors = error;
                throw error;
            }
        
            // Check contentType, so far we only support (raw) Data.
            var contentType = asn1.derToOid(capture.contentType);
            if (contentType !== forge.pki.oids.data) {
                throw new Error('Unsupported PKCS#7 message. ' +
                    'Only wrapped ContentType Data supported.');
            }
        
            if (capture.encryptedContent) {
                var content = '';
                if (forge.util.isArray(capture.encryptedContent)) {
                    for (var i = 0; i < capture.encryptedContent.length; ++i) {
                        if (capture.encryptedContent[i].type !== asn1.Type.OCTETSTRING) {
                            throw new Error('Malformed PKCS#7 message, expecting encrypted ' +
                                'content constructed of only OCTET STRING objects.');
                        }
                        content += capture.encryptedContent[i].value;
                    }
                } else {
                    content = capture.encryptedContent;
                }
                msg.encryptedContent = {
                    algorithm: asn1.derToOid(capture.encAlgorithm),
                    parameter: forge.util.createBuffer(capture.encParameter.value),
                    content: forge.util.createBuffer(content)
                };
            }
        
            if (capture.content) {
                var content = '';
                if (forge.util.isArray(capture.content)) {
                    for (var i = 0; i < capture.content.length; ++i) {
                        if (capture.content[i].type !== asn1.Type.OCTETSTRING) {
                            throw new Error('Malformed PKCS#7 message, expecting ' +
                                'content constructed of only OCTET STRING objects.');
                        }
                        content += capture.content[i].value;
                    }
                } else {
                    content = capture.content;
                }
                msg.content = forge.util.createBuffer(content);
            }
        
            msg.version = capture.version.charCodeAt(0);
            msg.rawCapture = capture;
        
            return capture;
        }
        
        function _attributeToAsn1(attr) {
            var value;
        
            // TODO: generalize to support more attributes
            if (attr.type === forge.pki.oids.contentType) {
                value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    asn1.oidToDer(attr.value).getBytes());
            } else if (attr.type === forge.pki.oids.messageDigest) {
                value = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false,
                    attr.value.bytes());
            } else if (attr.type === forge.pki.oids.signingTime) {
                /* Note per RFC 2985: Dates between 1 January 1950 and 31 December 2049
                  (inclusive) MUST be encoded as UTCTime. Any dates with year values
                  before 1950 or after 2049 MUST be encoded as GeneralizedTime. [Further,]
                  UTCTime values MUST be expressed in Greenwich Mean Time (Zulu) and MUST
                  include seconds (i.e., times are YYMMDDHHMMSSZ), even where the
                  number of seconds is zero.  Midnight (GMT) must be represented as
                  "YYMMDD000000Z". */
                // TODO: make these module-level constants
                var jan_1_1950 = new Date('1950-01-01T00:00:00Z');
                var jan_1_2050 = new Date('2050-01-01T00:00:00Z');
                var date = attr.value;
                if (typeof date === 'string') {
                    // try to parse date
                    var timestamp = Date.parse(date);
                    if (!isNaN(timestamp)) {
                        date = new Date(timestamp);
                    } else if (date.length === 13) {
                        // YYMMDDHHMMSSZ (13 chars for UTCTime)
                        date = asn1.utcTimeToDate(date);
                    } else {
                        // assume generalized time
                        date = asn1.generalizedTimeToDate(date);
                    }
                }
        
                if (date >= jan_1_1950 && date < jan_1_2050) {
                    value = asn1.create(
                        asn1.Class.UNIVERSAL, asn1.Type.UTCTIME, false,
                        asn1.dateToUtcTime(date));
                } else {
                    value = asn1.create(
                        asn1.Class.UNIVERSAL, asn1.Type.GENERALIZEDTIME, false,
                        asn1.dateToGeneralizedTime(date));
                }
            }
        
            // TODO: expose as common API call
            // create a RelativeDistinguishedName set
            // each value in the set is an AttributeTypeAndValue first
            // containing the type (an OID) and second the value
            return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // AttributeType
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    asn1.oidToDer(attr.type).getBytes()),
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, value ? [value] : attr.asn1Value)
            ]);
        }
        
        function _signersToAsn1(signers) {
            var ret = [];
            for (var i = 0; i < signers.length; ++i) {
                ret.push(_signerToAsn1(signers[i]));
            }
            return ret;
        }
        
        function _signerToAsn1(obj) {
            // SignerInfo
            var rval = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // version
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
                    asn1.integerToDer(obj.version).getBytes()),
                // issuerAndSerialNumber
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    // name
                    forge.pki.distinguishedNameToAsn1({ attributes: obj.issuer }),
                    // serial
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,
                        forge.util.hexToBytes(obj.serialNumber))
                ]),
                // digestAlgorithm
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                    // algorithm
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                        asn1.oidToDer(obj.digestAlgorithm).getBytes()),
                    // parameters (null)
                    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
                ])
            ]);
        
            // authenticatedAttributes (OPTIONAL)
            if (obj.authenticatedAttributesAsn1) {
                // add ASN.1 previously generated during signing
                rval.value.push(obj.authenticatedAttributesAsn1);
            }
        
            // digestEncryptionAlgorithm
            rval.value.push(asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                // algorithm
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,
                    asn1.oidToDer(obj.signatureAlgorithm).getBytes()),
                // parameters (null)
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
            ]));
        
            // encryptedDigest
            rval.value.push(asn1.create(
                asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, obj.signature));
        
            // unauthenticatedAttributes (OPTIONAL)
            if (obj.unauthenticatedAttributes.length > 0) {
                // [1] IMPLICIT
                var attrsAsn1 = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, []);
                for (var i = 0; i < obj.unauthenticatedAttributes.length; ++i) {
                    var attr = obj.unauthenticatedAttributes[i];
                    attrsAsn1.values.push(_attributeToAsn1(attr));
                }
                rval.value.push(attrsAsn1);
            }
        
            return rval;
        }
        