# node-signpdf-pades
Sign PDF documents with a PAdES Baseline B compatibile signature utilizing node-signpdf

--

This repo contains some sample code to achieve PAdES-compliant signatues using the `node-singpdf` library. In order to do this, I had to slightly modify the underlying code for the library and its dependency `node-forge`.

These changes were necessary in order to include the _Certificate Identification Version 2_ field in the signed attributes, which contains the SHA256 hash of the certificate used to create the signature.

Credits for the code and some comments are provided at the top of files.

> **I don't plan to keep this repo updated and patched.** Please, use it as inspiration and make sure to always follow the most recent security best practices.
> 
> If you discover any issue with the code or want to suggest changes or improvements, feel free to report it in the Issues section of open a PR. I, hower, cannot insure they will be addressed.

# How to use

In oreder to use this code you need to install `node-forge` and `node-signpdf` using NPM

```
npm i node-forge node-signpdf
```

The code was created and tested using Forge version `1.3.1` and `node-signpdf` version `1.5.1`. There are links to the correct version of the libraries github in the code itself.

To use the function place the signing certificate in a folder of choice and update the path at the top of the `signPDF` file.
Then call the default function as 
```
const document = fs.readFileSync(__dirname + "/document.pdf");
const signedDocument = await documentSigner(document, {
    reason: "Reason for the signature",
    field: "Name of the signature field"
});
```

## Testing
The files signed with this library passed the _ETSI EN 319 142-2 v1.1.1 Additional PAdES signatures profiles_ tests performed by
[PAdES Conformance Checker](https://signatures-conformance-checker.etsi.org/pub/index.php) by ETSI.

They also seem valid when tested using [DSS Demostration WebApp](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation), which reported

![image](https://github.com/Xevolab/node-signpdf-pades/assets/20073894/9a415a15-3697-4565-aa24-ae31129bfe19)

## Limitations
The code does not deal with visible signatures, meaning that it signs the whole document by adding an invisibile signature field. If there is interest in the future, I can work on code snippet to also add a custom signature text.
