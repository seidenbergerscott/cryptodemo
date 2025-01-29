import streamlit as st
import time
import re
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

###############################################################################
# 1) A cached resource: the GLOBAL store for the entire app (shared by all)
###############################################################################
@st.cache_resource
def get_class_data():
    """
    This returns a dictionary that persists across all user sessions
    while the Streamlit server is running.

    We'll store:
      class_directory = { username: {"pub_pem": <str>, "registered_at": <float>} }
      messages        = list of { from_user, to_user, ciphertext_hex }
    """
    return {
        "class_directory": {},
        "messages": []
    }

###############################################################################
# 2) Helper: Purge old users (registered >24h ago)
###############################################################################
def purge_old_users(class_data, max_age_seconds=86400):
    """
    Removes directory entries older than `max_age_seconds` (defaults to 24h).
    """
    now = time.time()
    to_remove = []
    for username, info in list(class_data["class_directory"].items()):
        if (now - info["registered_at"]) > max_age_seconds:
            to_remove.append(username)
    for user in to_remove:
        del class_data["class_directory"][user]

###############################################################################
# 3) Username Sanitization
###############################################################################
def sanitize_username(raw_name: str) -> str:
    """
    - Keep only alphanumerics [a-zA-Z0-9].
    - Truncate to 10 characters.
    """
    sanitized = re.sub(r"[^a-zA-Z0-9]", "", raw_name)  # remove non-alphanumeric
    sanitized = sanitized[:10]  # limit to 10 chars
    return sanitized

###############################################################################
# 4) Cryptographic Helper Functions
###############################################################################
def generate_key_pair():
    """Generate a 2048-bit RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def key_to_pem(key, is_private=False):
    """Convert an RSA key (private or public) to PEM format."""
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

def encrypt_message(public_key, message: bytes) -> bytes:
    """Encrypt message with RSA (OAEP + SHA-256)."""
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(private_key, ciphertext: bytes) -> bytes:
    """Decrypt message with RSA (OAEP + SHA-256)."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def sign_message(private_key, message: bytes) -> bytes:
    """Sign message with RSA (PSS + SHA-256)."""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    """Verify RSA signature (PSS + SHA-256). Returns True/False."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

###############################################################################
# 5) Single Streamlit App with Tabs
###############################################################################
def main():
    st.set_page_config(page_title="Crypto Demo", layout="wide")

    # Top layout: logo + titles
    col_logo, col_title = st.columns([0.15, 0.85])
    with col_logo:
        try:
            st.image("logo.png", use_container_width=True)
        except:
            pass
    with col_title:
        st.title("CS5833 Cryptography Demo")
        st.subheader("By Scott Seidenberger")

    # Create three tabs
    tabs = st.tabs(["Crypto Basics", "Multiuser", "Public Directory"])

    ############################################################################
    # TAB 1: "Crypto Basics"
    ############################################################################
    with tabs[0]:
        st.header("Crypto Basics")

        # 1. HASHING DEMO
        st.markdown("### 1. Hashing Demo")
        with st.expander("Show/Hide Hashing", expanded=True):
            message_to_hash = st.text_input("Enter a message to hash:", "Hello, Students!")
            
            col1, col2 = st.columns([1,1])
            with col1:
                if st.button("Compute Hashes"):
                    md5_hash = hashlib.md5(message_to_hash.encode()).hexdigest()
                    sha256_hash = hashlib.sha256(message_to_hash.encode()).hexdigest()
                    st.write(f"**MD5:** `{md5_hash}`")
                    st.write(f"**SHA-256:** `{sha256_hash}`")

            with col2:
                HASH_SNIPPET = """\
import hashlib

md5_hash = hashlib.md5(message.encode()).hexdigest()
sha256_hash = hashlib.sha256(message.encode()).hexdigest()
"""
                if st.button("Show Hashing Code"):
                    st.code(HASH_SNIPPET, language="python")

        # 2. RSA KEY GENERATION (ALICE, BOB, TRUDY)
        st.markdown("### 2. Generate RSA Keys (Alice, Bob, Trudy)")
        with st.expander("Show/Hide Key Generation", expanded=False):
            if "alice_keys" not in st.session_state:
                st.session_state.alice_keys = None
            if "bob_keys" not in st.session_state:
                st.session_state.bob_keys = None
            if "trudy_keys" not in st.session_state:
                st.session_state.trudy_keys = None

            col1, col2 = st.columns([1,1])
            with col1:
                if st.button("Generate/Regenerate All Keys"):
                    st.session_state.alice_keys = generate_key_pair()
                    st.session_state.bob_keys = generate_key_pair()
                    st.session_state.trudy_keys = generate_key_pair()
                    st.success("New 2048-bit RSA key pairs generated for Alice, Bob, and Trudy!")
            with col2:
                KEYGEN_SNIPPET = """\
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
return private_key, public_key
"""
                if st.button("Show Key Generation Code"):
                    st.code(KEYGEN_SNIPPET, language="python")

            if st.session_state.alice_keys and st.session_state.bob_keys and st.session_state.trudy_keys:
                alice_private_key, alice_public_key = st.session_state.alice_keys
                bob_private_key, bob_public_key = st.session_state.bob_keys
                trudy_private_key, trudy_public_key = st.session_state.trudy_keys

                st.write("**Alice's Private Key (PEM):**")
                st.code(key_to_pem(alice_private_key, is_private=True))

                st.write("**Alice's Public Key (PEM):**")
                st.code(key_to_pem(alice_public_key, is_private=False))

                st.write("**Bob's Private Key (PEM):**")
                st.code(key_to_pem(bob_private_key, is_private=True))

                st.write("**Bob's Public Key (PEM):**")
                st.code(key_to_pem(bob_public_key, is_private=False))

                st.write("**Trudy's Private Key (PEM):**")
                st.code(key_to_pem(trudy_private_key, is_private=True))

                st.write("**Trudy's Public Key (PEM):**")
                st.code(key_to_pem(trudy_public_key, is_private=False))
            else:
                st.warning("Keys have not been generated yet.")

        # 3. RSA ENCRYPTION/DECRYPTION
        st.markdown("### 3. RSA Encryption/Decryption")
        with st.expander("Show/Hide Encryption/Decryption", expanded=False):
            if st.session_state.bob_keys and st.session_state.trudy_keys:
                bob_private_key, bob_public_key = st.session_state.bob_keys
                trudy_private_key, trudy_public_key = st.session_state.trudy_keys

                msg_enc = st.text_input("Message to encrypt with Bob's public key:",
                                        "This is a top-secret message for Bob only.")

                col1, col2 = st.columns([1,1])
                with col1:
                    if st.button("Encrypt with Bob's Public Key"):
                        ciphertext = encrypt_message(bob_public_key, msg_enc.encode())
                        st.session_state.encrypted_message = ciphertext
                        st.success("Encrypted successfully with Bob's public key!")
                        st.write("**Ciphertext (hex):**")
                        st.code(ciphertext.hex(), language="plaintext")

                with col2:
                    ENCRYPT_SNIPPET = """\
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
"""
                    if st.button("Show Encryption Code"):
                        st.code(ENCRYPT_SNIPPET, language="python")

                if "encrypted_message" in st.session_state and st.session_state.encrypted_message:
                    st.write("#### Decrypt the Ciphertext (Try Bob or Trudy)")

                    dec_col1, dec_col2 = st.columns([1,1])
                    with dec_col1:
                        if st.button("Decrypt w/ Bob's Private Key"):
                            try:
                                decrypted = decrypt_message(bob_private_key, st.session_state.encrypted_message)
                                st.success(f"**Bob's Decryption Succeeded**. Message: {decrypted.decode('utf-8')}")
                            except Exception as e:
                                st.error(f"Failure with Bob's key: {e}")

                    with dec_col2:
                        if st.button("Decrypt w/ Trudy's Private Key"):
                            try:
                                _ = decrypt_message(trudy_private_key, st.session_state.encrypted_message)
                                st.error("**Trudy's Decryption Succeeded?** Should NOT happen with correct RSA!")
                            except Exception:
                                st.error("**Trudy's Decryption Failed** (what we expect).")

                    DECRYPT_SNIPPET = """\
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
"""
                    if st.button("Show Decryption Code"):
                        st.code(DECRYPT_SNIPPET, language="python")
            else:
                st.warning("Generate keys for Bob & Trudy first.")

        # 4. RSA SIGNING/VERIFICATION
        st.markdown("### 4. RSA Signing & Verification")
        with st.expander("Show/Hide Signing/Verification", expanded=False):
            if st.session_state.alice_keys and st.session_state.trudy_keys:
                alice_private_key, alice_public_key = st.session_state.alice_keys
                trudy_private_key, trudy_public_key = st.session_state.trudy_keys

                msg_sign = st.text_input("Message to be signed by Alice:",
                                         "Alice says: Hello, class!")

                col1, col2 = st.columns([1,1])
                with col1:
                    if st.button("Sign w/ Alice's Private Key"):
                        # Use the sign_message function
                        signature = sign_message(alice_private_key, msg_sign.encode())
                        st.session_state.signature = signature
                        st.success("Message signed successfully with Alice's private key!")
                        st.write("**Signature (hex):**")
                        st.code(signature.hex(), language="plaintext")

                with col2:
                    SIGN_SNIPPET = """\
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
"""
                    if st.button("Show Signing Code"):
                        st.code(SIGN_SNIPPET, language="python")

                # Verification
                if "signature" in st.session_state and st.session_state.signature:
                    st.write("#### Verify the Signature (Alice or Trudy)")

                    ver_col1, ver_col2 = st.columns([1,1])

                    with ver_col1:
                        if st.button("Verify w/ Alice's Public Key"):
                            valid = verify_signature(alice_public_key, msg_sign.encode(), st.session_state.signature)
                            if valid:
                                st.success(f"**Verification Succeeded**: Alice indeed signed the message: '{msg_sign}'")
                            else:
                                st.error(f"Verification failed with Alice's public key for message: '{msg_sign}'")

                    with ver_col2:
                        if st.button("Verify w/ Trudy's Public Key"):
                            valid = verify_signature(trudy_public_key, msg_sign.encode(), st.session_state.signature)
                            if valid:
                                st.error(f"**Verification Succeeded** with Trudy's key for message: '{msg_sign}'? Should NOT happen!")
                            else:
                                st.error(f"**Verification Failed** with Trudy's key for message: '{msg_sign}' (correct).")

                    VERIFY_SNIPPET = """\
public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
"""
                    if st.button("Show Verification Code"):
                        st.code(VERIFY_SNIPPET, language="python")
            else:
                st.warning("Generate keys for Alice & Trudy first.")


    ############################################################################
    # TAB 2: "Multiuser"
    ############################################################################
    with tabs[1]:
        st.header("Multiuser RSA Demo")
        st.write(
            "Each participant can generate their own local key pair, "
            "pick a username (up to 10 alphanumeric characters), "
            "register their public key in a shared directory, "
            "and exchange encrypted messages with classmates."
        )

        class_data = get_class_data()

        # Local session state for personal keys
        if "my_private_key" not in st.session_state:
            st.session_state.my_private_key = None
            st.session_state.my_public_key = None

        st.markdown("### A) Generate Your Local Key Pair")
        if not st.session_state.my_private_key:
            if st.button("Generate My Key Pair (Local)"):
                priv, pub = generate_key_pair()
                st.session_state.my_private_key = priv
                st.session_state.my_public_key = pub
                st.success("Generated your local key pair!")
        else:
            st.info("You already have a local key pair this session.")
            st.write("**My Private Key (PEM):**")
            st.code(key_to_pem(st.session_state.my_private_key, True))
            st.write("**My Public Key (PEM):**")
            st.code(key_to_pem(st.session_state.my_public_key, False))

            if st.button("Regenerate My Key Pair"):
                priv, pub = generate_key_pair()
                st.session_state.my_private_key = priv
                st.session_state.my_public_key = pub
                st.success("Regenerated your local key pair.")

        st.markdown("### B) Register Your Public Key in the Directory")
        raw_name = st.text_input("Your Username (alphanumeric, up to 10 chars)", "")
        if st.button("Register My Public Key"):
            if not st.session_state.my_public_key:
                st.error("Generate your local key pair first.")
            else:
                sanitized = sanitize_username(raw_name)
                if not sanitized:
                    st.error("After sanitizing, no valid characters left. Please try again!")
                else:
                    pub_pem = key_to_pem(st.session_state.my_public_key, is_private=False)
                    now = time.time()
                    class_data["class_directory"][sanitized] = {
                        "pub_pem": pub_pem,
                        "registered_at": now
                    }
                    st.success(f"Registered/updated username '{sanitized}' in the global directory.")

        st.markdown("### C) Send an Encrypted Message to a Classmate")
        if not class_data["class_directory"]:
            st.warning("No users in directory yet.")
        else:
            all_users = list(class_data["class_directory"].keys())
            chosen_recipient = st.selectbox("Recipient Username", all_users)
            msg_to_send = st.text_input("Message to Send", "Hello from me to you!")
            if st.button("Encrypt & Send"):
                if st.session_state.my_private_key is None:
                    st.error("You haven't generated your own key pair yet.")
                else:
                    recipient_info = class_data["class_directory"].get(chosen_recipient)
                    if not recipient_info:
                        st.error("Recipient not found in directory.")
                    else:
                        recipient_pub_pem = recipient_info["pub_pem"]
                        try:
                            recipient_public_key = serialization.load_pem_public_key(recipient_pub_pem.encode())
                            ciphertext = encrypt_message(recipient_public_key, msg_to_send.encode())
                            me = sanitize_username(raw_name)
                            class_data["messages"].append({
                                "from_user": me,
                                "to_user": chosen_recipient,
                                "ciphertext_hex": ciphertext.hex()
                            })
                            st.success(f"Encrypted and sent message to '{chosen_recipient}'.")
                        except Exception as e:
                            st.error(f"Error encrypting: {e}")

        st.markdown("### D) Check Your Inbox & Decrypt")
        st.write("Press 'R' on your keyboard to reload and check for messages.")
        me = sanitize_username(raw_name)
        if not me:
            st.info("Enter a valid username above to see your messages.")
        else:
            purge_old_users(class_data)
            my_inbox = [
                m for m in class_data["messages"]
                if m["to_user"] == me
            ]
            if my_inbox:
                for i, msg in enumerate(my_inbox):
                    st.write(f"**Message #{i+1}** from: {msg['from_user']}")
                    st.code(msg["ciphertext_hex"], language="plaintext")
                    if st.button(f"Decrypt Message #{i+1}"):
                        if not st.session_state.my_private_key:
                            st.error("No local private key! Generate it first.")
                        else:
                            try:
                                ct_bytes = bytes.fromhex(msg["ciphertext_hex"])
                                plaintext = decrypt_message(st.session_state.my_private_key, ct_bytes)
                                st.success(f"Decrypted: {plaintext.decode('utf-8')}")
                            except Exception as e:
                                st.error(f"Decryption failed: {e}")
            else:
                st.info("No messages for you yet.")

    ############################################################################
    # TAB 3: "Public Directory"
    ############################################################################
    with tabs[2]:
        st.header("Public Directory")
        st.markdown(
            "**Note**: The directory resets every 24 hours. "
            "Any entry older than 24 hours is automatically removed."
        )

        class_data = get_class_data()
        purge_old_users(class_data)

        directory = class_data["class_directory"]
        if directory:
            for user, info in directory.items():
                st.markdown(f"**Username**: {user}")
                st.code(info["pub_pem"], language="plaintext")
        else:
            st.info("No one has registered yet or the directory was just cleared.")

if __name__ == "__main__":
    main()
