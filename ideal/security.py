import re
import os
import hashlib
import base64
import logging
from io import BytesIO
import six

from OpenSSL import crypto
from lxml import etree

from ideal.utils import render_to_string, IDEAL_NAMESPACES


logger = logging.getLogger(__name__)


class Security(object):
    def get_fingerprint(self, private_certificate):
        """
        Return the certificate SHA1-fingerprint.

        :param private_certificate: File path to the merchant's own certificate file (ie. cert.cer).

        :return: Fingerprint as a string.
        """
        cert_data = open(private_certificate, "rb").read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        sha1_fingerprint = cert.digest("sha1")

        fingerprint = sha1_fingerprint.zfill(40).lower().replace(b":", b"")

        del cert_data, cert

        return fingerprint

    def get_message_digest(self, msg, digest_method=None):
        """
        Return the message digeset of given ``msg`` using ``digest_method`` as hashing function.

        :param msg: The message to create a digest of.
        :param digest_method: The hashing function to use, as string (optional). Default\: 'sha256'.

        :return: Base 64 encoded message digest.
        """
        if digest_method is None:
            digest_method = 'sha256'

        digest_func = getattr(hashlib, digest_method.split('#')[-1])

        hashed = digest_func(msg.encode('utf-8'))

        return base64.b64encode(hashed.digest())

    def get_signature(self, signed_info, private_key, password):
        """
        Return a signature for the ``signed_info`` string, using provided ``private_key`` and ``password`` to unlock the
        private key.

        :param signed_info: The XML snippet containing only the signed info part as string.
        :param private_key: File path to the Merchant's private key file.
        :param password: Password to unlock the ``private_key``.

        :return: Base 64 encoded signature.
        """
        if isinstance(signed_info, six.text_type):
            signed_info = signed_info.encode('utf-8')

        if isinstance(password, six.text_type):
            password = password.encode('utf-8')

        signed_info_tree = etree.parse(BytesIO(signed_info))
        f = BytesIO()
        signed_info_tree.write_c14n(f, exclusive=True)
        signed_info_str = f.getvalue()

        privatekey_data = open(private_key, "r").read()

        pkey = crypto.load_privatekey(
            crypto.FILETYPE_PEM, privatekey_data, password)

        sign = crypto.sign(pkey, signed_info_str, "sha256")

        del pkey

        return base64.b64encode(sign)

    def sign_message(self, msg, private_certificate, private_key, password):
        """
        Return the signed message.

        :param msg: The unsigned XML message to sign.
        :param private_certificate: File path to the Merchant's certificate file.
        :param private_key: File path to the Merchant's private key file.
        :param password: Password to unlock the ``private_key``.

        :return: The signed message.
        """

        signed_info = render_to_string('templates/signed_info.xml', {
            'digest_value': str(self.get_message_digest(msg), 'utf-8')
        })

        signature = render_to_string('templates/signature.xml', {
            'signed_info': signed_info,
            'signature_value': str(self.get_signature(
                signed_info, private_key, password), 'utf-8'),
            'key_name': str(self.get_fingerprint(private_certificate), 'utf-8'),
        })

        content, container_end = msg.rsplit('<', 1)

        return ''.join([content, signature, '<', container_end])

    def verify(self, xml_document, certificates):
        """
        Return ``True`` if the ``xml_document`` can be verified against any of the ``certificates``.

        :param xml_document: The XML document, as string, to verify.
        :param certificates: List of certificates. Any certificate may match to return a positive result.

        :return: ``True``, if verification succeded. ``False`` otherwise.
        """

        # Remove the signature, strip the XML header and strip trailing newlines.
        unsigned_xml = re.sub(re.compile('<\?.*\?>\n?|<Signature.*</Signature>', flags=re.DOTALL), '', str(xml_document, 'utf-8')).rstrip('\n')

        xml_tree = etree.parse(BytesIO(xml_document))

        signature = xml_tree.xpath('xmldsig:Signature', namespaces=IDEAL_NAMESPACES)[0]
        signed_info = signature.xpath('xmldsig:SignedInfo', namespaces=IDEAL_NAMESPACES)[0]

        digest_method = signed_info.xpath('xmldsig:Reference/xmldsig:DigestMethod',
                namespaces=IDEAL_NAMESPACES)[0].get('Algorithm')

        digest_value = signed_info.xpath('xmldsig:Reference/xmldsig:DigestValue',
                namespaces=IDEAL_NAMESPACES)[0].text

        # Verify message digest: Signature should be about the unsigned XML.
        if digest_value.encode('utf-8') != self.get_message_digest(unsigned_xml, digest_method):
            return False

        # Get signature properties.
        c14n_method = signed_info.xpath('xmldsig:CanonicalizationMethod',
                namespaces=IDEAL_NAMESPACES)[0].get('Algorithm')
        signature_method = signed_info.xpath('xmldsig:SignatureMethod',
                namespaces=IDEAL_NAMESPACES)[0].get('Algorithm')
        transforms = [el.get('Algorithm') for el in
                signed_info.xpath('xmldsig:Reference/xmldsig:Transforms/xmldsig:Transform',
                namespaces=IDEAL_NAMESPACES)]

        signature_value = signature.xpath('xmldsig:SignatureValue', namespaces=IDEAL_NAMESPACES)[0].text
        key_name = signature.xpath('xmldsig:KeyInfo/xmldsig:KeyName', namespaces=IDEAL_NAMESPACES)[0].text

        key_name = key_name.encode('utf-8').lower()

        # Apply canonicalization.
        signed_info_tree = etree.ElementTree(signed_info)
        f = BytesIO()
        signed_info_tree.write_c14n(f, exclusive=(c14n_method == 'http://www.w3.org/2001/10/xml-exc-c14n#'))
        signed_info_str = f.getvalue()

        # TODO: Apply transformations (currently not needed).

        # Go through the list of installed certificates.
        for cert_file in certificates:
            # Match the given XML signature's fingerprint (KeyName) with the fingerprints of one of the installed
            # certificates.
            if key_name == self.get_fingerprint(cert_file):

                cert_data = open(cert_file, "rb").read()
                # pkey = crypto.load_publickey(crypto.FILETYPE_PEM, cert_data)
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
                x509 = crypto.X509()
                x509.set_pubkey(cert.get_pubkey())

                verify = crypto.verify(
                    x509, base64.b64decode(signature_value),
                    signed_info_str, 'sha256')

                del cert_data, cert, x509

                # it will return None when it's been verified
                return verify is None

        return False
