import streamlit as st
from sphincs import SPHINCS_Hypertree
import json
import os
from datetime import datetime
import hashlib
import pandas as pd
import time
# ======================================================
# Configuration Streamlit (TOUJOURS EN PREMIER)
# ======================================================
st.set_page_config(
    page_title="SPHINCS+ Demo",
    page_icon="🔐",
    layout="wide"
)

# ======================================================
# Constantes & fichiers
# ======================================================
HISTORY_FILE = "history.json"

# ======================================================
# Fonctions utilitaires
# ======================================================
def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def save_history(history):
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)

def hash_message(msg: bytes) -> str:
    return hashlib.sha256(msg).hexdigest()

def load_css():
    if os.path.exists("styles/style.css"):
        with open("styles/style.css") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()

# ======================================================
# Initialisation SPHINCS+
# ======================================================
if "sph" not in st.session_state:
    st.session_state.sph = SPHINCS_Hypertree()

if "sk" not in st.session_state or "pk" not in st.session_state:
    st.session_state.sk, st.session_state.pk = st.session_state.sph.gen_keypair()

sph = st.session_state.sph
sk = st.session_state.sk
pk = st.session_state.pk

# ======================================================
# Interface
# ======================================================
st.title("🔐 Démonstration SPHINCS+")
st.markdown(
    "Application pédagogique permettant de **signer et vérifier des messages ou fichiers** "
    "à l’aide d’un prototype inspiré de **SPHINCS+ (post-quantique)**.\n\n"
    "⚠️ Implémentation académique – **non destinée à un usage réel en production**."
)

st.markdown("---")

# ======================================================
# 1️⃣ Choix du message / fichier
# ======================================================
st.subheader("1️⃣ Choix du message ou fichier à signer")

col1, col2 = st.columns([2, 1])

with col1:
    msg_input = st.text_area("💬 Message à signer")

with col2:
    file_input = st.file_uploader("📂 Ou choisir un fichier")

if file_input is not None:
    msg_bytes = file_input.read()
    filename = file_input.name
    st.caption(f"📄 Fichier chargé : {filename} ({len(msg_bytes)} bytes)")
elif msg_input:
    msg_bytes = msg_input.encode()
    filename = "Texte libre"
else:
    msg_bytes = None
    filename = None

# ======================================================
# 2️⃣ Signature
# ======================================================
st.markdown("---")
st.subheader("2️⃣ Générer la signature")

if st.button("🔏 Signer"):
    if msg_bytes is None:
        st.error("Veuillez fournir un message ou un fichier.")
    else:
        sig = sph.sign(msg_bytes, sk)

        st.session_state.last_signature = sig
        st.session_state.last_message = msg_bytes

        st.success(f"Signature générée ({len(sig)} bytes)")

        st.text_area(
            "Signature (aperçu)",
            sig.hex()[:120] + "...",
            height=100
        )

        st.download_button(
            "📥 Télécharger la signature (.sig)",
            data=sig,
            file_name="signature.sig",
            mime="application/octet-stream"
        )

        # Historique
        history = load_history()
        history.append({
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "fichier": filename,
            "hash_message": hash_message(msg_bytes),
            "taille_signature": len(sig),
            "statut": "Signé"
        })
        save_history(history)

# ======================================================
# 3️⃣ Vérification
# ======================================================
st.markdown("---")
st.subheader("3️⃣ Vérifier une signature")

col1, col2, col3 = st.columns([2, 2, 1])

with col1:
    verify_file = st.file_uploader("📂 Fichier à vérifier", key="vf")

with col2:
    verify_text = st.text_area("💬 Message à vérifier", key="vt")

with col3:
    sig_upload = st.file_uploader("📄 Signature (.sig)", type="sig")

if st.button("✅ Vérifier"):
    if sig_upload is None:
        st.error("Veuillez charger une signature (.sig).")
    else:
        sig_bytes = sig_upload.read()

        if verify_file is not None:
            verify_bytes = verify_file.read()
            verify_name = verify_file.name
        elif verify_text:
            verify_bytes = verify_text.encode()
            verify_name = "Texte libre"
        else:
            st.error("Veuillez fournir un message ou un fichier à vérifier.")
            verify_bytes = None

        if verify_bytes is not None:
            valid = sph.verify(sig_bytes, verify_bytes, pk)

            if valid:
                st.success("Signature valide ✅")
            else:
                st.error("Signature invalide ❌")

            # Historique
            history = load_history()
            history.append({
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "fichier": verify_name,
                "hash_message": hash_message(verify_bytes),
                "taille_signature": len(sig_bytes),
                "statut": "Valide ✅" if valid else "Invalide ❌"
            })
            save_history(history)

# ======================================================
# Historique
# ======================================================
st.markdown("---")
st.subheader("📜 Historique des signatures")

history = load_history()
if history:
    df = pd.DataFrame(history)
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("Aucune opération enregistrée.")

# ------------------------ 5️⃣ Animation étape par étape ------------------------
st.markdown("---")
st.subheader("🚀 Animation pédagogique SPHINCS+")

msg_for_anim = st.text_area("Entrez un message pour l'animation", "Hello SPHINCS+")
msg_bytes_anim = msg_for_anim.encode() if msg_for_anim else b''

if st.button("▶️ Lancer l'animation"):
    if not msg_bytes_anim:
        st.error("Veuillez entrer un message")
    else:
        animation_container = st.container()

        with animation_container:
            # Étape 1
            st.markdown("**Étape 1 : Message original**")
            st.text(msg_bytes_anim)
            time.sleep(1)

            # Étape 2
            r = sph.hash_prf(sk[:sph.n], msg_bytes_anim)
            msg_hash = sph.hash_f(r + msg_bytes_anim)
            st.markdown("**Étape 2 : Randomizer + Hash**")
            st.text(f"Randomizer: {r.hex()[:16]}...\nHash: {msg_hash.hex()[:16]}...")
            time.sleep(1)

            # Étape 3
            msg_indices = [msg_hash[i] % (2**sph.t) for i in range(sph.k)]
            fors_sk = sph.fors_gen_sk(sk[:sph.n], 1000)
            fors_sig = sph.fors_sign(msg_indices, fors_sk)
            st.markdown("**Étape 3 : Signature FORS générée**")
            st.text(f"{len(fors_sig)} feuilles + chemins")
            time.sleep(1)

            # Étape 4
            fors_root = sph.fors_verify(fors_sig, msg_indices)
            wots_sk = sph.wots_gen_sk(sk[:sph.n], 0)
            wots_sig = sph.wots_sign(fors_root, wots_sk)
            st.markdown("**Étape 4 : Signature WOTS+ générée**")
            st.text(f"{len(wots_sig)} chaînes")
            time.sleep(1)

            # Étape 5
            hypertree_nodes = [sph.hash_f((r + layer.to_bytes(1,'big'))) for layer in range(sph.d)]
            st.markdown("**Étape 5 : Hypertree ajoutée**")
            st.text(f"{len(hypertree_nodes)} nœuds de couche")
            time.sleep(1)

            # Étape 6
            sig_full = sph.sign(msg_bytes_anim, sk)
            st.markdown("**Étape 6 : Signature complète**")
            st.text(f"Taille totale : {len(sig_full)} bytes")


# ======================================================
# Aide
# ======================================================
st.info(
    "💡 **Tests conseillés** :\n"
    "- Signez un fichier ou message\n"
    "- Téléchargez la signature\n"
    "- Modifiez le contenu → vérification invalide\n"
    "- Restaurez le contenu exact → signature valide"
)












