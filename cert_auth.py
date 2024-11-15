import base64
import datetime
import json
import os
import uuid
import secrets
import sha256
import crsa
import re
from aes_enc import AESdecrypt
from aes_enc import AESencrypt


class RSAsign:
    @classmethod
    def generate_rsa_key_pair(cls, size=512):
        p, q, d, e, n, prv_pem, pub_pem = crsa.RSA.keygen(size)
        return {
            "public_key": pub_pem,
            "private_key": prv_pem}

    @classmethod
    def encryptrsa(cls, message, prv_key):
        encryptor = crsa.RSA.from_pem(pem=prv_key, key_type=crsa.Key.PRIVATE, reverse=True)
        return encryptor.encrypt(message)

    @classmethod
    def decryptrsa(cls, message, pub_key, utf8b=True):
        encryptor = crsa.RSA.from_pem(pem=pub_key, key_type=crsa.Key.PUBLIC, reverse=True)
        return encryptor.decrypt(message, utf8b)


class CertClient:
    common_name: str
    _key_pair: dict
    certificate: dict
    public_key: str

    def __init__(self, common_name='Client', key_pair=None, certificate=None):
        self.common_name = common_name
        if key_pair is None:
            self._key_pair = RSAsign.generate_rsa_key_pair()
        if certificate is not None:
            self.certificate = certificate
        self.public_key = self._key_pair['public_key']

    def generate_csr(self):
        def csr_to_pem(csr_dict):
            csr_json = json.dumps(csr_dict)
            csr_b64 = base64.b64encode(csr_json.encode()).decode()
            pem_csr = "-----BEGIN CERTIFICATE REQUEST-----\n"
            pem_csr += "\n".join([csr_b64[i:i + 64] for i in range(0, len(csr_b64), 64)])
            pem_csr += "\n-----END CERTIFICATE REQUEST-----\n"
            return pem_csr

        csr = {
            "subject": {
                "common_name": self.common_name,
                "public_key": self._key_pair["public_key"]
            },
            "signature_algorithm": "SHA256withRSA"
        }
        csr["signature"] = RSAsign.encryptrsa(
            sha256.generate_hash(str(csr).encode()),
            self._key_pair["private_key"]
        )
        return csr_to_pem(csr)

    def assign_certificate(self, certificate: dict):
        self.certificate = certificate

    @classmethod
    def verify_certificate(cls, ca_name, certificate):
        certificate = certificate.copy()
        ca = CertAuth.call_ca(ca_name)
        signature = RSAsign.decryptrsa(certificate["signature"], ca.public_key, False)
        certificate.pop("signature")
        if signature != sha256.generate_hash(str(certificate).encode()) or \
                certificate["validity"]["not_before"] > datetime.datetime.utcnow() \
                or certificate["validity"]["not_after"] <= datetime.datetime.utcnow() \
                or ca.is_cert_revoked(certificate["serial_number"]):
            return False
        else:
            return True

    @classmethod
    def certificate_to_file(cls, certificate):
        pem_cert = '-----BEGIN CERTIFICATE-----\n'
        pem_cert += base64.b64encode(certificate['certificate']).decode('utf-8')
        pem_cert += '\n-----END CERTIFICATE-----\n'
        file_name = str(uuid.uuid4())
        with open(file_name + '.cert', 'w') as f:
            f.write(pem_cert)
        return file_name

    @classmethod
    def csr_to_file(cls, csr):
        pem_csr = '-----BEGIN CERTIFICATE REQUEST-----\n'
        pem_csr += base64.b64encode(csr).decode('utf-8')
        pem_csr += '\n-----END CERTIFICATE REQUEST-----\n'
        file_name = str(uuid.uuid4())
        with open(file_name + '.csr', 'w') as f:
            f.write(pem_csr)
        return file_name


class CertAuth(CertClient):
    _crl_file_path: str
    _ca_list = []
    _crl_pass_path: str

    def __init__(self, common_name='CA', key_pair=None, certificate=None):
        super().__init__(common_name=common_name, key_pair=key_pair, certificate=certificate)
        self._crl_file_path = 'crl_' + common_name + '.dat'
        self._crl_pass_path = common_name + str(int.from_bytes(secrets.randbits(64).to_bytes(64, 'big'), 'big')) + \
                              '.pass'
        if certificate is None:
            self.certificate = {
                "version": 3,
                "serial_number": 1,
                "signature_algorithm": "SHA256withRSA",
                "subject": {
                    "common_name": self.common_name,
                    "public_key": self._key_pair["public_key"]
                },
                "extensions": {
                    "key_usage": "key_cert_sign,crl_sign",
                    "basic_constraints": {
                        "is_ca": True
                    }
                }
            }
            self.certificate["signature"] = RSAsign.encryptrsa(
                sha256.generate_hash(str(self.certificate).encode('utf-8')),
                self._key_pair["private_key"]
            )
        pass_phrase = secrets.randbits(128)
        with open(self._crl_pass_path, 'w') as f:
            f.write(str(pass_phrase.to_bytes((pass_phrase.bit_length() + 7) // 8, 'big')))
        open(self._crl_file_path, 'w').close()
        CertAuth._ca_list.append(self)

    def revoke_certificate(self, certificate_serial_number):
        certificate_serial_number = certificate_serial_number + "\x00" \
                                    * ((len(certificate_serial_number) + 7) // 8 - len(certificate_serial_number))
        serial_number_bytes = certificate_serial_number.encode()
        pem_revoked_cert = '-----BEGIN X509 CRL ENTRY-----\n'
        pem_revoked_cert += base64.b64encode(serial_number_bytes).decode('utf-8')
        pem_revoked_cert += '\n-----END X509 CRL ENTRY-----\n'

        AESdecrypt.decrypt_file(self._crl_file_path, self._crl_file_path + '.d', self._crl_pass_path)
        with open(self._crl_file_path + '.d', 'a') as f:
            f.write(pem_revoked_cert)
        AESencrypt.encrypt_file(self._crl_file_path + '.d', self._crl_file_path, self._crl_pass_path)
        os.remove(self._crl_file_path + '.d')

    def generate_certificate(self, pem_csr):
        def generate_serial_number():
            timestamp = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')

            rand_num = secrets.randbits(32)

            serial_number = f'{timestamp}{rand_num:05d}'

            return serial_number

        def pem_to_csr(pem_csr):
            csr_data = re.search(r"-----BEGIN CERTIFICATE REQUEST-----(.*)-----END CERTIFICATE REQUEST-----", pem_csr,
                                 re.DOTALL)
            if not csr_data:
                raise ValueError("Invalid CSR format")

            csr_json = base64.b64decode(csr_data.group(1).replace("\n", "")).decode()
            csr_dict = json.loads(csr_json)
            return csr_dict

        csr = pem_to_csr(pem_csr)
        certificate = {
            "version": 3,
            "serial_number": generate_serial_number(),
            "signature_algorithm": "SHA256withRSA",
            "issuer": self.certificate["subject"],
            "validity": {
                "not_before": datetime.datetime.utcnow(),
                "not_after": datetime.datetime.utcnow() + datetime.timedelta(days=365)
            },
            "subject": {
                "common_name": csr["subject"]["common_name"],
                "public_key": csr["subject"]["public_key"]
            },
            "csr": csr,
            "extensions": {
                "key_usage": "digital_signature",
                "basic_constraints": {
                    "is_ca": False
                }
            }
        }
        certificate["signature"] = RSAsign.encryptrsa(
            sha256.generate_hash(str(certificate).encode()),
            self._key_pair['private_key']
        )
        return certificate

    def is_cert_revoked(self, serial_number):
        try:
            AESdecrypt.decrypt_file(self._crl_file_path, self._crl_file_path + '.d', self._crl_pass_path)
            with open(self._crl_file_path + '.d', "r") as f:
                for line in f:
                    if line.startswith("-----"):
                        continue

                    if serial_number == str(base64.b64decode(line.strip().encode()))[2:-1]:
                        return True
                return False
        finally:
            AESencrypt.encrypt_file(self._crl_file_path + '.d', self._crl_file_path, self._crl_pass_path)
            os.remove(self._crl_file_path + '.d')

    @classmethod
    def call_ca(cls, common_name):
        for ca in cls._ca_list:
            if ca.certificate['subject']['common_name'] == common_name:
                return ca
        raise Exception('CA not found')




