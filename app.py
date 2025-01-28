import streamlit as st
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

###############################################################################
# GLOBAL STORE: A cached resource (shared by all users/sessions)
###############################################################################
@st.cache_resource
def get_class_data():
    """
    Returns a dictionary that persists across all user sessions while the
    Streamlit server is running. This acts as a simple global 'database':
    - class_directory: { username -> public_key_pem }
    - messages: list of { from_user, to_user, ciphertext_hex }
    """
    return {
        "class_directory": {},
        "messages": []
    }

###############################################################################
# CRYPTO HELPER FUNCTIONS
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
# CODE SNIPPETS (Strings)
###############################################################################
KEYGEN_SNIPPET = """\
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
return private_key, public_key
"""

HASH_SNIPPET = """\
import hashlib

md5_hash = hashlib.md5(message.encode()).hexdigest()
sha256_hash = hashlib.sha256(message.encode()).hexdigest()
"""

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

###############################################################################
# MAIN APP
###############################################################################
def main():
    # Optional: page config
    # st.set_page_config(page_title="CS5833 Combined Demo", layout="wide")

    # Top layout: logo + titles (optional)
    col_logo, col_title = st.columns([0.15, 0.85])
    with col_logo:
        st.image("logo.png", use_container_width=True)

    with col_title:
        st.title("CS5833 Cryptography Demo")
        st.subheader("By Scott Seidenberger")

    # TABS: we have 3 tabs:
    tabs = st.tabs(["Crypto Basics", "Multiplayer", "Public Directory"])

    ############################################################################
    # TAB 1: "Crypto Basics"
    ############################################################################
    with tabs[0]:
        st.header("Crypto Basics")

        st.markdown("### 1. Hashing Demo")
        with st.expander("Show/Hide Hashing", expanded=True):
            message_to_hash = st.text_input("Enter a message to hash:", "Hello, Students!")
            
            col1, col2 = st.columns([1,1])
            with col1:
                if st.button("Compute Hashes", key="hash_btn"):
                    md5_hash = hashlib.md5(message_to_hash.encode()).hexdigest()
                    sha256_hash = hashlib.sha256(message_to_hash.encode()).hexdigest()
                    st.write(f"**MD5:** `{md5_hash}`")
                    st.write(f"**SHA-256:** `{sha256_hash}`")

            with col2:
                if st.button("Show Hashing Code", key="hash_code_btn"):
                    st.code(HASH_SNIPPET, language="python")

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
                if st.button("Generate/Regenerate All Keys", key="gen_keys_btn"):
                    st.session_state.alice_keys = generate_key_pair()
                    st.session_state.bob_keys = generate_key_pair()
                    st.session_state.trudy_keys = generate_key_pair()
                    st.success("New 2048-bit RSA key pairs generated for Alice, Bob, and Trudy!")
            with col2:
                if st.button("Show Key Generation Code", key="show_keygen_code_btn"):
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
                st.warning("Keys have not been generated yet. Click the button above.")

        st.markdown("### 3. RSA Encryption/Decryption")
        with st.expander("Show/Hide Encryption/Decryption", expanded=False):
            if st.session_state.bob_keys and st.session_state.trudy_keys:
                bob_private_key, bob_public_key = st.session_state.bob_keys
                trudy_private_key, trudy_public_key = st.session_state.trudy_keys

                msg_enc = st.text_input("Message to encrypt with Bob's public key:",
                                        "This is a top-secret message for Bob only.",
                                        key="msg_enc_basics")

                col1, col2 = st.columns([1,1])
                with col1:
                    if st.button("Encrypt with Bob's Public Key", key="encrypt_btn_basics"):
                        ciphertext = encrypt_message(bob_public_key, msg_enc.encode())
                        st.session_state.encrypted_message_basics = ciphertext
                        st.success("Encrypted successfully with Bob's public key!")
                        st.write("**Ciphertext (hex)**:")
                        st.code(ciphertext.hex(), language="plaintext")

                with col2:
                    if st.button("Show Encryption Code", key="encrypt_code_btn_basics"):
                        st.code(ENCRYPT_SNIPPET, language="python")

                if "encrypted_message_basics" in st.session_state and st.session_state.encrypted_message_basics:
                    st.write("#### Decrypt the Ciphertext (Try Bob or Trudy)")
                    
                    dec_col1, dec_col2 = st.columns([1,1])
                    with dec_col1:
                        if st.button("Decrypt w/ Bob's Private Key", key="dec_bob_btn_basics"):
                            try:
                                decrypted = decrypt_message(bob_private_key, st.session_state.encrypted_message_basics)
                                st.success(f"**Bob's Decryption Succeeded**. Message:\n{decrypted.decode('utf-8')}")
                            except Exception as e:
                                st.error(f"Failure with Bob's key: {e}")

                    with dec_col2:
                        if st.button("Decrypt w/ Trudy's Private Key", key="dec_trudy_btn_basics"):
                            try:
                                _ = decrypt_message(trudy_private_key, st.session_state.encrypted_message_basics)
                                st.error("**Trudy's Decryption Succeeded?** Should NEVER happen with correct RSA!")
                            except Exception:
                                st.error("**Trudy's Decryption Failed** (correct).")

                    if st.button("Show Decryption Code", key="dec_code_btn_basics"):
                        st.code(DECRYPT_SNIPPET, language="python")
            else:
                st.warning("Generate keys for Bob & Trudy first.")

        st.markdown("### 4. RSA Signing & Verification")
        with st.expander("Show/Hide Signing/Verification", expanded=False):
            if st.session_state.alice_keys and st.session_state.trudy_keys:
                alice_private_key, alice_public_key = st.session_state.alice_keys
                trudy_private_key, trudy_public_key = st.session_state.trudy_keys

                msg_sign = st.text_input("Message to be signed by Alice:",
                                         "Alice says: Hello, class!",
                                         key="msg_sign_basics")

                col1, col2 = st.columns([1,1])
                with col1:
                    if st.button("Sign w/ Alice's Private Key", key="sign_btn_basics"):
                        signature = sign_message(alice_private_key, msg_sign.encode())
                        st.session_state.signature_basics = signature
                        st.success("Message signed successfully with Alice's private key!")
                        st.write("**Signature (hex)**:")
                        st.code(signature.hex(), language="plaintext")

                with col2:
                    if st.button("Show Signing Code", key="sign_code_btn_basics"):
                        st.code(SIGN_SNIPPET, language="python")

                if "signature_basics" in st.session_state and st.session_state.signature_basics:
                    st.write("#### Verify the Signature (Alice or Trudy)")

                    ver_col1, ver_col2 = st.columns([1,1])
                    with ver_col1:
                        if st.button("Verify w/ Alice's Public Key", key="verify_alice_btn_basics"):
                            valid = verify_signature(alice_public_key, msg_sign.encode(), st.session_state.signature_basics)
                            if valid:
                                st.success("**Verification Succeeded**: Alice indeed signed this.")
                            else:
                                st.error("Verification failed with Alice's public key? Unexpected.")

                    with ver_col2:
                        if st.button("Verify w/ Trudy's Public Key", key="verify_trudy_btn_basics"):
                            valid = verify_signature(trudy_public_key, msg_sign.encode(), st.session_state.signature_basics)
                            if valid:
                                st.error("**Verification Succeeded w/ Trudy's key?** Should NOT happen if RSA is correct!")
                            else:
                                st.error("**Verification Failed** with Trudy's key (correct).")

                    if st.button("Show Verification Code", key="verify_code_btn_basics"):
                        st.code(VERIFY_SNIPPET, language="python")
            else:
                st.warning("Generate keys for Alice & Trudy first.")


    ############################################################################
    # TAB 2: "Multiplayer"
    ############################################################################
    with tabs[1]:
        st.header("Multiplayer RSA Demo")
        st.write(
            "In this tab, each participant can generate their own local key pair, "
            "pick a username, register their public key in a shared directory, "
            "and send encrypted messages to each other."
        )

        # Access the global store
        class_data = get_class_data()

        # Local session: my private/public
        if "my_private_key" not in st.session_state:
            st.session_state.my_private_key = None
            st.session_state.my_public_key = None

        st.markdown("### A) Generate Your Local Key Pair")
        if not st.session_state.my_private_key:
            if st.button("Generate My Key Pair (Local)", key="gen_my_keypair"):
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

            if st.button("Regenerate My Key Pair", key="regen_my_keypair"):
                priv, pub = generate_key_pair()
                st.session_state.my_private_key = priv
                st.session_state.my_public_key = pub
                st.success("Regenerated your local key pair.")

        st.markdown("### B) Register Your Public Key in the Class Directory")
        username = st.text_input("Your Username (unique)", key="multiplayer_username")
        if st.button("Register My Public Key", key="register_btn"):
            if not username.strip():
                st.error("Please enter a username first.")
            elif st.session_state.my_public_key is None:
                st.error("You need to generate your local key pair first.")
            else:
                pub_pem = key_to_pem(st.session_state.my_public_key, False)
                class_data["class_directory"][username] = pub_pem
                st.success(f"Registered/updated '{username}' in the global directory.")

        st.markdown("### C) Send an Encrypted Message")
        if not class_data["class_directory"]:
            st.warning("No users in directory yet. Register someone first!")
        else:
            all_users = list(class_data["class_directory"].keys())
            chosen_recipient = st.selectbox("Recipient Username", all_users, key="chosen_recipient")
            msg_to_send = st.text_input("Message to Send", "Hello from me to you!", key="msg_to_send")
            if st.button("Encrypt & Send", key="send_msg_btn"):
                if chosen_recipient == username:
                    st.info("You're sending a message to yourself. Just a note.")
                if st.session_state.my_private_key is None:
                    st.error("You haven't generated your local key pair yet.")
                elif not username.strip():
                    st.error("You must enter your username above.")
                else:
                    # get recipient's pubkey
                    recipient_pub_pem = class_data["class_directory"].get(chosen_recipient)
                    if not recipient_pub_pem:
                        st.error("Recipient not found in directory.")
                    else:
                        recipient_public_key = serialization.load_pem_public_key(recipient_pub_pem.encode())
                        ciphertext = encrypt_message(recipient_public_key, msg_to_send.encode())

                        class_data["messages"].append({
                            "from_user": username,
                            "to_user": chosen_recipient,
                            "ciphertext_hex": ciphertext.hex()
                        })
                        st.success(f"Encrypted and sent message to '{chosen_recipient}'.")

        st.markdown("### D) Check Your Inbox & Decrypt")
        if not username.strip():
            st.info("Enter your username to see messages addressed to you.")
        else:
            my_inbox = [
                m for m in class_data["messages"]
                if m["to_user"] == username
            ]
            if my_inbox:
                for i, msg in enumerate(my_inbox):
                    st.write(f"**Message #{i+1}** from: {msg['from_user']}")
                    st.code(msg["ciphertext_hex"], language="plaintext")
                    if st.button(f"Decrypt Message #{i+1}", key=f"dec_inbox_{i}"):
                        if not st.session_state.my_private_key:
                            st.error("You have no local private key! Generate it first.")
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
        st.header("Public Key Directory")
        st.write(
            "This page displays all registered users and their public keys, "
            "so it doesn’t clutter the main page."
        )
        class_data = get_class_data()  # same global store
        directory = class_data["class_directory"]
        if directory:
            for user, pub_pem in directory.items():
                st.markdown(f"**Username**: {user}")
                st.code(pub_pem, language="plaintext")
        else:
            st.info("No one has registered yet.")


if __name__ == "__main__":
    main()
