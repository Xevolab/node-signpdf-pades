/**
 * Many thanks to @Hopding for the sample code snippet
 * https://github.com/Hopding/pdf-lib/issues/112#issuecomment-569085380
 * 
 * Huge thanks to @ElTimuro for this fix
 * https://github.com/vbuch/node-signpdf/pull/187
 */

import fs from 'fs';
import path from 'path';
const p12Buffer = fs.readFileSync(path.resolve(process.cwd(), "certificate.p12"));

import { SUBFILTER_ETSI_CADES_DETACHED, DEFAULT_BYTE_RANGE_PLACEHOLDER } from 'node-signpdf';

import customSigner from "./customPDFSigner"

const {
  PDFDocument,
  PDFName,
  PDFNumber,
  PDFHexString,
  PDFString,
  PDFArray, CharCodes
} = require('pdf-lib');

class PDFArrayCustom extends PDFArray {
  static withContext(context) {
    return new PDFArrayCustom(context);
  }

  clone(context) {
    const clone = PDFArrayCustom.withContext(context || this.context);
    for (let idx = 0, len = this.size(); idx < len; idx++) {
      clone.push(this.array[idx]);
    }
    return clone;
  }

  toString() {
    let arrayString = '[';
    for (let idx = 0, len = this.size(); idx < len; idx++) {
      arrayString += this.get(idx).toString();
      if (idx < len - 1) arrayString += ' ';
    }
    arrayString += ']';
    return arrayString;
  }

  sizeInBytes() {
    let size = 2;
    for (let idx = 0, len = this.size(); idx < len; idx++) {
      size += this.get(idx).sizeInBytes();
      if (idx < len - 1) size += 1;
    }
    return size;
  }

  copyBytesInto(buffer, offset) {
    const initialOffset = offset;

    buffer[offset++] = CharCodes.LeftSquareBracket;
    for (let idx = 0, len = this.size(); idx < len; idx++) {
      offset += this.get(idx).copyBytesInto(buffer, offset);
      if (idx < len - 1) buffer[offset++] = CharCodes.Space;
    }
    buffer[offset++] = CharCodes.RightSquareBracket;

    return offset - initialOffset;
  }
}

const SIGNATURE_LENGTH = 32768;

/**
 * documentSigner signs a PDF document with a P12 certificate using the
 * node-signpdf library.
 * It requires the following parameters:
 * - documentBytes: the PDF document to sign as a Buffer
 * - opts: an object containing the following optional parameters:
 *  - field: the name of the signature field
 *  - reason: the reason for the signature
 */
export default async function documentSigner(documentBytes, opts = {}) {

  const pdfDoc = await PDFDocument.load(documentBytes);
  const pages = pdfDoc.getPages();

  const ByteRange = PDFArrayCustom.withContext(pdfDoc.context);
  ByteRange.push(PDFNumber.of(0));
  ByteRange.push(PDFName.of(DEFAULT_BYTE_RANGE_PLACEHOLDER));
  ByteRange.push(PDFName.of(DEFAULT_BYTE_RANGE_PLACEHOLDER));
  ByteRange.push(PDFName.of(DEFAULT_BYTE_RANGE_PLACEHOLDER));

  const signatureDict = pdfDoc.context.obj({
    Type: 'Sig',
    Filter: 'Adobe.PPKLite',
    SubFilter: SUBFILTER_ETSI_CADES_DETACHED,
    ByteRange,
    Reason: PDFString.of(opts.reason || 'Electronic signature'),
    M: PDFString.fromDate(new Date()),
    Contents: PDFHexString.of('0'.repeat(SIGNATURE_LENGTH)),
  });
  const signatureDictRef = pdfDoc.context.register(signatureDict);

  const widgetDict = pdfDoc.context.obj({
    Type: 'Annot',
    Subtype: 'Widget',
    FT: 'Sig',
    Rect: [0, 0, 0, 0],
    V: signatureDictRef,
    T: PDFString.of(opts.field || 'Signature1'),
    F: 4,
    P: pages[0].ref,
  });
  const widgetDictRef = pdfDoc.context.register(widgetDict);

  // Add our signature widget to the first page
  pages[0].node.set(PDFName.of('Annots'), pdfDoc.context.obj([widgetDictRef]));

  // Create an AcroForm object containing our signature widget
  pdfDoc.catalog.set(
    PDFName.of('AcroForm'),
    pdfDoc.context.obj({
      SigFlags: 3,
      Fields: [widgetDictRef],
    }),
  );

  const modifiedPdfBytes = await pdfDoc.save({ useObjectStreams: false });

  const signedPdfBuffer = customSigner(new Buffer.from(modifiedPdfBytes), p12Buffer);

  return signedPdfBuffer;

}
