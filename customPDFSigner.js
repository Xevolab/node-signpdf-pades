/**
 * This file is a modified version of node-signpdf/src/signpdf.js from
 * node-signpdf v1.5.1
 * 
 * Node-signpdf is licensed under the MIT License, which allows for
 * commercial use, modification and redistribution, even in closed-source
 * software.
 * 
 * https://github.com/vbuch/node-signpdf/blob/5fb54ee2abfc30dda8b90dccee3e6e2a3083bb1b/src/signpdf.js
 */

/**
 * This file modifies the original node-signpdf/src/signpdf.js to support
 * ETSI EN 319 142-2 signatures [2].
 * 
 * Compared to the original file, this one removes the signingTime from the
 * signed attributes and adds the essSigningCertificateV2.
 * The attribute is defined in [2], but it is not implemented in node-signpdf.
 * The specification is based on RFC 5126 [4] and RFC 5035 [5].
 * 
 * References: 
 * [1] ETSI EN 319 142-1 - PAdES
 * https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.01.01_60/en_31914201v010101p.pdf
 * [2] ETSI EN 319 142-2 - PAdES - Additional PAdES signatures profiles
 * https://www.etsi.org/deliver/etsi_en/319100_319199/31914202/01.01.01_60/en_31914202v010101p.pdf
 * [3] ETSI EN 319 122-1 - CAdES - signer-attributes-v2 reference 5.2.6.1
 * https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.02.01_60/en_31912201v010201p.pdf
 * [4] RFC 5126 - CAdES - signer-attributes-v2 reference
 * https://www.rfc-editor.org/rfc/rfc5126#section-5.7.3
 * [5] RFC 5035 - CAdES - essSigningCertificateV2 reference
 * https://www.rfc-editor.org/rfc/rfc5035#section-3
 */

import forge from 'node-forge';
import SignPdfError from 'node-signpdf/dist/SignPdfError';
import { removeTrailingNewLine, findByteRange } from 'node-signpdf';

import fs from 'fs';

import createSignedData from './customCreateSignedData';

export default function sign(
	pdfBuffer,
	p12Buffer,
	additionalOptions = {},
) {
	const options = {
		asn1StrictParsing: false,
		passphrase: '',
		...additionalOptions,
	};

	if (!(pdfBuffer instanceof Buffer)) {
		throw new SignPdfError(
			'PDF expected as Buffer.',
			SignPdfError.TYPE_INPUT,
		);
	}
	if (!(p12Buffer instanceof Buffer)) {
		throw new SignPdfError(
			'p12 certificate expected as Buffer.',
			SignPdfError.TYPE_INPUT,
		);
	}

	let pdf = removeTrailingNewLine(pdfBuffer);

	// Find the ByteRange placeholder.
	const { byteRangePlaceholder } = findByteRange(pdf);

	if (!byteRangePlaceholder) {
		throw new SignPdfError(
			`Could not find empty ByteRange placeholder: ${byteRangePlaceholder}`,
			SignPdfError.TYPE_PARSE,
		);
	}

	const byteRangePos = pdf.indexOf(byteRangePlaceholder);

	// Calculate the actual ByteRange that needs to replace the placeholder.
	const byteRangeEnd = byteRangePos + byteRangePlaceholder.length;
	const contentsTagPos = pdf.indexOf('/Contents ', byteRangeEnd);
	const placeholderPos = pdf.indexOf('<', contentsTagPos);
	const placeholderEnd = pdf.indexOf('>', placeholderPos);
	const placeholderLengthWithBrackets = (placeholderEnd + 1) - placeholderPos;
	const placeholderLength = placeholderLengthWithBrackets - 2;
	const byteRange = [0, 0, 0, 0];
	byteRange[1] = placeholderPos;
	byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
	byteRange[3] = pdf.length - byteRange[2];
	let actualByteRange = `/ByteRange [${byteRange.join(' ')}]`;
	actualByteRange += ' '.repeat(byteRangePlaceholder.length - actualByteRange.length);

	// Replace the /ByteRange placeholder with the actual ByteRange
	pdf = Buffer.concat([
		pdf.slice(0, byteRangePos),
		Buffer.from(actualByteRange),
		pdf.slice(byteRangeEnd),
	]);

	// Remove the placeholder signature
	pdf = Buffer.concat([
		pdf.slice(0, byteRange[1]),
		pdf.slice(byteRange[2], byteRange[2] + byteRange[3]),
	]);

	// Convert Buffer P12 to a forge implementation.
	const forgeCert = forge.util.createBuffer(p12Buffer.toString('binary'));
	const p12Asn1 = forge.asn1.fromDer(forgeCert);
	const p12 = forge.pkcs12.pkcs12FromAsn1(
		p12Asn1,
		options.asn1StrictParsing,
		options.passphrase,
	);

	// Extract safe bags by type.
	// We will need all the certificates and the private key.
	const certBags = p12.getBags({
		bagType: forge.pki.oids.certBag,
	})[forge.pki.oids.certBag];
	const keyBags = p12.getBags({
		bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
	})[forge.pki.oids.pkcs8ShroudedKeyBag];

	const privateKey = keyBags[0].key;
	// Here comes the actual PKCS#7 signing.
	const p7 = createSignedData();
	// Start off by setting the content.
	p7.content = forge.util.createBuffer(pdf.toString('binary'));

	// Then add all the certificates (-cacerts & -clcerts)
	// Keep track of the last found client certificate.
	// This will be the public key that will be bundled in the signature.
	let certificate;
	Object.keys(certBags).forEach((i) => {
		const { publicKey } = certBags[i].cert;

		p7.addCertificate(certBags[i].cert);

		// Try to find the certificate that matches the private key.
		if (privateKey.n.compareTo(publicKey.n) === 0
			&& privateKey.e.compareTo(publicKey.e) === 0
		) {
			certificate = certBags[i].cert;
		}
	});

	if (typeof certificate === 'undefined') {
		throw new SignPdfError(
			'Failed to find a certificate that matches the private key.',
			SignPdfError.TYPE_INPUT,
		);
	}

	// Add a sha256 signer. That's what Adobe.PPKLite adbe.pkcs7.detached expects.
	// Note that the authenticatedAttributes order is relevant for correct
	// EU signature validation:
	// https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation
	p7.addSigner({
		key: privateKey,
		certificate,
		digestAlgorithm: forge.pki.oids.sha256,
		authenticatedAttributes: [
			{
				type: forge.pki.oids.contentType,
				value: forge.pki.oids.data,
			}, {
				type: forge.pki.oids.messageDigest,
				// value will be auto-populated at signing time
			},


			/**
			 * essSigningCertificate
			 * 
			 * https://www.rfc-editor.org/rfc/rfc2634#section-5
			 * 1.2.840.113549.1.9.16.2.12
			 * http://oid-info.com/get/1.2.840.113549.1.9.16.2.12
			 * 
			 * We are not using this type of attribute because the RFC says:
			 * 'The ESS signing-certificate attribute, defined in ESS [5], must
			 *  be used if the SHA-1 hashing algorithm is used.'
			 * [https://www.rfc-editor.org/rfc/rfc5126#section-5.7.3]
			 * 
			 * Which is not the case here, we are using SHA-256.
			 */


			/*
			 * essSigningCertificateV2
			 *
			 * https://www.rfc-editor.org/rfc/rfc5035#section-4
			 * 1.2.840.113549.1.9.16.2.47
			 * http://oid-info.com/get/1.2.840.113549.1.9.16.2.47
			 * 
			 */
			{
				name: "essSigningCertificateV2",
				type: "1.2.840.113549.1.9.16.2.47",

				/*
					SigningCertificateV2 ::=  SEQUENCE {
						certs        SEQUENCE OF ESSCertIDv2,
						policies     SEQUENCE OF PolicyInformation OPTIONAL
					}
				*/
				asn1Value: [forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [

					/*
						ESSCertIDv2 ::=  SEQUENCE {
							hashAlgorithm           AlgorithmIdentifier
									DEFAULT {algorithm id-sha256},
							certHash                 Hash,
							issuerSerial             IssuerSerial OPTIONAL
						}
					*/
					forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
						forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false, forge.asn1.oidToDer("2.16.840.1.101.3.4.2.1").getBytes()),
						forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false,
							forge.util.hexToBytes(calculateHash(p12Buffer))
						),
					])

				])]
			}
		]
	});

	// Sign in detached mode.
	p7.sign({ detached: true });

	fs.writeFileSync('signatureDer.txt', forge.asn1.toDer(p7.toAsn1()).getBytes(), 'binary');
	fs.writeFileSync('signaturePem.txt', forge.pkcs7.messageToPem(p7), 'binary');

	/*
	 * To debug the output, use this:
	console.log(forge.pkcs7.messageToPem(p7));
	 * 
	 * To show the contents of the certificates in the signature, use this:
	 * openssl pkcs7 -inform PEM -print_certs -text -in signature.p7
	 * To show the contents of the signature, use this:
	 * openssl asn1parse -in signature.txt -i
	 */

	// Check if the PDF has a good enough placeholder to fit the signature.
	const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
	// placeholderLength represents the length of the HEXified symbols but we're
	// checking the actual lengths.
	if ((raw.length * 2) > placeholderLength) {
		throw new SignPdfError(
			`Signature exceeds placeholder length: ${raw.length * 2} > ${placeholderLength}`,
			SignPdfError.TYPE_INPUT,
		);
	}

	let signature = Buffer.from(raw, 'binary').toString('hex');

	// Pad the signature with zeroes so the it is the same length as the placeholder
	signature += Buffer
		.from(String.fromCharCode(0).repeat((placeholderLength / 2) - raw.length))
		.toString('hex');

	// Place it in the document.
	pdf = Buffer.concat([
		pdf.slice(0, byteRange[1]),
		Buffer.from(`<${signature}>`),
		pdf.slice(byteRange[1]),
	]);

	// Magic. Done.
	return pdf;
}

import crypto from 'crypto';
function calculateHash(buffer) {
	const hash = crypto.createHash('sha256');
	hash.update(buffer);
	return hash.digest("hex");
}
