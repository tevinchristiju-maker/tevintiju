# app.py
import streamlit as st
import json, os
from phe import paillier
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
from base64 import b64encode, b64decode

VOTES_FILE = "votes.json"
ELECTION_FILE = "election_keys.json"

st.set_page_config(page_title="Secure Voting (Paillier + RSA)", layout="centered")

# ---------- Helpers ----------
def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_json(path, default):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return default

def ensure_files():
    if not os.path.exists(VOTES_FILE):
        save_json(VOTES_FILE, {"votes": []})
    if not os.path.exists(ELECTION_FILE):
        save_json(ELECTION_FILE, {})

def generate_rsa_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem.decode(), pub_pem.decode()

def sign_message(priv_pem_str: str, message_bytes: bytes) -> str:
    priv = serialization.load_pem_private_key(priv_pem_str.encode(), password=None)
    sig = priv.sign(
        message_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return b64encode(sig).decode()

def verify_signature(pub_pem_str: str, message_bytes: bytes, signature_b64: str) -> bool:
    pub = serialization.load_pem_public_key(pub_pem_str.encode())
    sig = b64decode(signature_b64)
    try:
        pub.verify(sig, message_bytes,
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                   hashes.SHA256())
        return True
    except Exception:
        return False

# ---------- Election / keys ----------
ensure_files()
election = load_json(ELECTION_FILE, {})

st.title("Secure Voting Prototype — Paillier Homomorphic Tally")
st.markdown("This demo uses *Paillier* (additive HE) for vote tally, and *RSA* for signatures.")

menu = st.sidebar.selectbox("Mode", ["Create Election (admin)", "Voter - Register / Cast Vote", "Tally (admin)"])

# Admin: Create election
if menu == "Create Election (admin)":
    st.header("Create / Reset Election")
    if st.button("Generate new Paillier keypair (1024 bits)"):
        public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)
        # Save n and g? phe objects are picklable but we'll store numbers
        election_data = {
            "public_n": public_key.n,
            "private_p": private_key.p,   # store private for demo only - in real deploy keep secret
            "private_q": private_key.q
        }
        save_json(ELECTION_FILE, election_data)
        save_json(VOTES_FILE, {"votes": []})
        st.success("New election keys generated and votes cleared.")
        st.write("Public modulus n (truncated):", str(public_key.n)[:60], "...")
    else:
        if election:
            st.write("Existing election public modulus n (truncated):")
            st.write(str(election.get("public_n", ""))[:120], "...")
        else:
            st.info("No election keys yet. Generate new keys to begin.")

# Voter registration & voting
elif menu == "Voter - Register / Cast Vote":
    st.header("Voter Registration / Cast Vote")
    st.markdown("1) Generate your RSA keypair (for signing) or paste an existing private key PEM.  \n2) Select candidate and cast vote.  \n*Note:* The app stores only the Paillier-encrypted vote and your signature (not your private key).")

    # Candidates - simple sample list
    candidates_input = st.text_input("Enter candidates (comma separated)", value="Alice,Bob,Charlie")
    candidates = [c.strip() for c in candidates_input.split(",") if c.strip()]
    st.write("Candidates:", candidates)

    # Generate RSA keys
    if st.button("Generate RSA keypair for me"):
        priv_pem, pub_pem = generate_rsa_keypair()
        st.session_state["priv_pem"] = priv_pem
        st.session_state["pub_pem"] = pub_pem
        st.success("RSA keypair generated. Save your private key securely (you'll need it to sign).")
        st.code(priv_pem, language="text")
        st.code(pub_pem, language="text")

    st.write("---")
    uploaded_priv = st.text_area("Paste your RSA private key PEM here (or press Generate RSA keypair)", height=160)
    if "priv_pem" in st.session_state and not uploaded_priv:
        uploaded_priv = st.session_state["priv_pem"]

    voter_id = st.text_input("Voter ID (e.g., roll no or student id)", value="")
    selected = st.radio("Select candidate to vote for", candidates)

    if st.button("Cast Vote"):
        if not election:
            st.error("Election keys not found. Admin must create election first.")
        elif not uploaded_priv:
            st.error("Please provide/paste your RSA private key PEM.")
        elif not voter_id:
            st.error("Please enter your voter id.")
        else:
            # Prepare one-hot vector as integers
            vector = [1 if c == selected else 0 for c in candidates]  # e.g. [0,1,0]
            # Paillier encrypt each element
            public_key = paillier.PaillierPublicKey(n=int(election["public_n"]))
            # Encrypt vector
            ciphertexts = [public_key.encrypt(v) for v in vector]  # phe EncryptedNumber objects
            # We will serialize each ciphertext as (ciphertext.ciphertext()) base64? phe has .ciphertext() int
            serial_ct = []
            for ct in ciphertexts:
                serial_ct.append({"ciphertext": str(ct.ciphertext()), "exponent": ct.exponent})
            # Create a message string to sign: canonical JSON of candidate + serialized ciphertexts
            message_dict = {"voter_id_hash": hashlib.sha256(voter_id.encode()).hexdigest(), "candidate": selected, "ciphertexts": serial_ct}
            message_bytes = json.dumps(message_dict, sort_keys=True).encode()
            # signature using provided private key PEM
            try:
                signature = sign_message(uploaded_priv, message_bytes)
            except Exception as e:
                st.error("Failed to sign. Make sure private key PEM is correct.")
                st.exception(e)
                signature = None

            if signature:
                # Save vote record (do NOT store private key)
                votes = load_json(VOTES_FILE, {"votes": []})
                votes["votes"].append({
                    "voter_id_hash": hashlib.sha256(voter_id.encode()).hexdigest(),
                    "pub_note": None,  # optional: we can store public key if voter wants to publish it (not required)
                    "candidate_claim": selected,
                    "ciphertexts": serial_ct,
                    "signature": signature
                })
                save_json(VOTES_FILE, votes)
                st.success("Vote cast successfully! Your signature stored with encrypted vote.")
                st.json(votes["votes"][-1])

# Admin tally
elif menu == "Tally (admin)":
    st.header("Tally Votes (admin)")

    if not election:
        st.error("No election keys found. Generate keys first in Create Election.")
    else:
        votes_data = load_json(VOTES_FILE, {"votes": []})
        st.write(f"Total votes recorded (encrypted): {len(votes_data['votes'])}")
        if len(votes_data["votes"]) == 0:
            st.info("No votes to tally yet.")
        else:
            st.write("Sample stored vote (encrypted):")
            st.json(votes_data["votes"][0])

            # Verify signatures for all votes (requires voters provide public keys or public keys stored)
            st.markdown("**Signature verification (best-effort):**")
            verify_ok = st.checkbox("Attempt signature verification? (only works if voter public keys were stored)", value=False)
            if verify_ok:
                verified = 0
                for rec in votes_data["votes"]:
                    pub = rec.get("pub_note")  # we didn't store pub by default
                    if pub:
                        # reconstruct message and verify (same canonicalization as signing)
                        msg = {"voter_id_hash": rec["voter_id_hash"], "candidate": rec["candidate_claim"], "ciphertexts": rec["ciphertexts"]}
                        if verify_signature(pub, json.dumps(msg, sort_keys=True).encode(), rec["signature"]):
                            verified += 1
                st.write(f"Verified signatures: {verified} / {len(votes_data['votes'])} (only if public keys were supplied)")

            # Homomorphic tally
            if st.button("Perform homomorphic tally (decrypt counts)"):
                # Reconstruct Paillier public/private key
                pub = paillier.PaillierPublicKey(n=int(election["public_n"]))
                priv = paillier.PaillierPrivateKey(pub, int(election["private_p"]), int(election["private_q"]))
                # Sum ciphertexts element-wise
                # First, deserialize ciphertexts (ciphertext int and exponent)
                # We'll use EncryptedNumber from phe by creating it via paillier.EncryptedNumber
                from phe import EncryptedNumber
                # initialize sums as ciphertext for zero
                num_candidates = len(votes_data["votes"][0]["ciphertexts"])
                sums = [None]*num_candidates
                for rec in votes_data["votes"]:
                    for i, item in enumerate(rec["ciphertexts"]):
                        c_int = int(item["ciphertext"])
                        exponent = int(item["exponent"])
                        enc_num = EncryptedNumber(pub, c_int, exponent)

                        if sums[i] is None:
                            sums[i] = enc_num
                        else:
                            sums[i] = sums[i] + enc_num  # homomorphic addition
                # decrypt sums
                counts = [priv.decrypt(s) for s in sums]
                st.success("Tally complete. Decrypted counts:")
                tally = dict(zip([f"Candidate {i+1}" for i in range(len(counts))], counts))
                # Better to present with candidate names if available (we stored in app state)
                st.write(tally)
                st.write("Candidate indices -> counts. Map indices by the order used when voting.")

st.markdown("***")
st.caption("This is a demo prototype for academic use. In a real deployment, never store private keys in plaintext and use secure key management and authentication.")
