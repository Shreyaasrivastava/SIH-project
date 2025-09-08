import json
import base64
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
import sys
import os

# Use a placeholder for the app ID, which would be provided by your environment
__app_id = "your-unique-app-id"

# --- Certificate Generation Logic ---

def generate_ecc_key():
    """Generates an Elliptic Curve private key for digital signing."""
    # Using secp256r1 curve, a NIST standard
    return ec.generate_private_key(ec.SECP256R1(), default_backend())

def create_x509_certificate(private_key, common_name="Wipe Signing Authority"):
    """
    Creates a self-signed X.509 certificate.
    This certificate acts as the verifiable digital identity of the signing authority.
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Rajasthan"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Vanasthali"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"IT Asset Recycling Solutions"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        # Certificate is valid for 10 years
        datetime.now(timezone.utc) + timedelta(days=365*10)
    ).sign(private_key, hashes.SHA256(), default_backend())

    return cert

def sign_data(private_key, data):
    """Signs a given data payload using the provided ECC private key."""
    # The data must be a byte string.
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

def create_json_certificate(wipe_details, signature, public_key_pem):
    """
    Creates a JSON certificate containing all wipe details and the digital signature.
    """
    certificate_data = {
        "certificate_id": wipe_details["certificate_id"],
        "device_info": wipe_details["device_info"],
        "wipe_details": wipe_details["wipe_details"],
        "timestamp": wipe_details["timestamp"],
        "app_id": __app_id,
        "digital_signature_base64": base64.b64encode(signature).decode('utf-8'),
        "public_key_pem": public_key_pem
    }
    return json.dumps(certificate_data, indent=4)

def create_pdf_certificate(wipe_details, signature_base64, public_key_pem, output_filename):
    """
    Creates a PDF certificate with a clear and professional layout.
    
    Note: This version does not include a cryptographically embedded signature
    using pyhanko, as that requires a more complex setup. The signature is
    included as text on the document.
    """
    c = canvas.Canvas(output_filename, pagesize=letter)

    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        name='TitleStyle',
        parent=styles['Heading1'],
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
        fontSize=20,
        spaceAfter=15
    )
    header_style = ParagraphStyle(
        name='HeaderStyle',
        parent=styles['Heading3'],
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
        fontSize=14,
        spaceAfter=10
    )
    normal_style = ParagraphStyle(
        name='NormalStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        spaceAfter=10
    )
    sig_style = ParagraphStyle(
        name='SignatureStyle',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8,
        spaceAfter=5
    )

    story = []
    
    # Title
    story.append(Paragraph("Data Wiping Certificate of EraseX", title_style))
    
    # Certificate ID and Timestamp
    story.append(Paragraph(f"<b>Certificate ID:</b> {wipe_details['certificate_id']}", normal_style))
    story.append(Paragraph(f"<b>Date of data wiping:</b> {wipe_details['timestamp']}", normal_style))
    
    # Device Information Section
    story.append(Paragraph("<b>Device Information</b>", header_style))
    for key, value in wipe_details['device_info'].items():
        story.append(Paragraph(f"<b>{key}:</b> {value}", normal_style))
    
    # Wipe Details Section
    story.append(Paragraph("<b>Wipe Details</b>", header_style))
    for key, value in wipe_details['wipe_details'].items():
        story.append(Paragraph(f"<b>{key}:</b> {value}", normal_style))
    
    # Verification Statement
    story.append(Paragraph(
        "This certificate attests that the data on the specified device has been securely "
        "erased in accordance with NIST SP 800-88 guidelines. The erasure process "
        "is verified and the integrity of this certificate is guaranteed by the "
        "digital signature below.", normal_style)
    )
    
    # Digital Signature Section
    story.append(Paragraph("<b>Digital Signature for Verification</b>", header_style))
    story.append(Paragraph(
        "The integrity of this document can be verified using the public key and signature.",
        normal_style
    ))
    story.append(Paragraph(f"<b>Signature:</b> {signature_base64}", sig_style))
    story.append(Paragraph(f"<b>Public Key:</b> {public_key_pem}", sig_style))
    
    doc = SimpleDocTemplate(output_filename, pagesize=letter)
    doc.build(story)
    
    print(f"PDF certificate saved to {output_filename}")


if __name__ == "__main__":
    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Generate the ECC private key that will sign the wipe certificates
    signer_private_key = generate_ecc_key()
    signer_public_key = signer_private_key.public_key()

    # 2. Create and save the self-signed X.509 certificate
    # This certificate represents the identity of the "Wipe Signing Authority"
    print("Generating X.509 certificate...")
    signer_cert = create_x509_certificate(signer_private_key)
    signer_cert_path = os.path.join(script_dir, "signer_certificate.pem")
    with open(signer_cert_path, "wb") as f:
        f.write(signer_cert.public_bytes(serialization.Encoding.PEM))
    print(f"X.509 certificate saved to {signer_cert_path}")
    
    # 3. Simulate a data wiping event and generate details
    wipe_details = {
        "certificate_id": "WIPE-CERT-123456789",
        "device_info": {
            "device_type": "Laptop",
            "manufacturer": "Dell",
            "model": "XPS 15",
            "serial_number": "SN1234567890"
        },
        "wipe_details": {
            "method": "NIST SP 800-88 Purge",
            "wiped_drives": ["/dev/sda", "/dev/sdb"],
            "verification_status": "Passed"
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # 4. Convert the wipe details to a canonical JSON string for signing
    data_to_be_signed = json.dumps(wipe_details, sort_keys=True).encode('utf-8')

    # 5. Sign the data using the signer's private key
    signature = sign_data(signer_private_key, data_to_be_signed)

    # 6. Serialize the signer's public key to PEM format for storage
    public_key_pem = signer_public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # 7. Generate the JSON certificate
    json_certificate = create_json_certificate(
        wipe_details, signature, public_key_pem
    )
    json_output_path = os.path.join(script_dir, f"certificate_{wipe_details['certificate_id']}.json")
    with open(json_output_path, "w") as f:
        f.write(json_certificate)
    print(f"JSON certificate saved to {json_output_path}")

    # 8. Generate the PDF certificate
    pdf_output_path = os.path.join(script_dir, f"certificate_{wipe_details['certificate_id']}.pdf")
    signature_base64 = base64.b64encode(signature).decode('utf-8')
    create_pdf_certificate(wipe_details, signature_base64, public_key_pem, pdf_output_path)

    print("\nCertificate generation complete. For third-party verification, you can "
          "share the JSON and PDF files along with the public key.")

    # --- Verification Example (Optional, for demonstration) ---
    def verify_signature(public_key, data, signature):
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


    # --- Third-party verification (for demonstration only) ---
    print("\n--- Third-party verification (for demonstration only) ---")
    data_to_be_verified = json.dumps(wipe_details, sort_keys=True).encode('utf-8')
    is_valid = verify_signature(signer_public_key, data_to_be_verified, signature)

    if is_valid:
        print("Signature verification successful: The certificate is authentic.")
    else:
        print("Signature verification failed: The certificate may be tampered with.")

