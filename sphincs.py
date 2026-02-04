import hashlib
import secrets
from typing import List, Tuple

class SPHINCS_Hypertree:
    def __init__(self):
        self.n = 16       # longueur des hachages
        self.w = 16       # paramètre Winternitz
        self.h = 8        # hauteur totale hypertree
        self.d = 3        # nombre de couches
        self.k = 10       # nombre d'arbres FORS
        self.t = 4        # hauteur des arbres FORS
        self.len_1 = 32
        self.len_2 = 3
        self.len = self.len_1 + self.len_2

    # ----- Fonctions de hachage -----
    def hash_f(self, x: bytes) -> bytes:
        return hashlib.sha256(x).digest()[:self.n]

    def hash_h(self, x: bytes, y: bytes) -> bytes:
        return hashlib.sha256(x + y).digest()[:self.n]

    def hash_prf(self, key: bytes, addr: bytes) -> bytes:
        return hashlib.sha256(key + addr).digest()[:self.n]

    # ----- Conversion base-w -----
    def to_base_w(self, x: bytes, out_len: int) -> List[int]:
        out = []
        total_bits = len(x) * 8
        bits_per_digit = 4
        for i in range(out_len):
            if i * bits_per_digit < total_bits:
                byte_idx = (i * bits_per_digit) // 8
                bit_offset = (i * bits_per_digit) % 8
                if byte_idx < len(x):
                    if bit_offset <= 4:
                        digit = (x[byte_idx] >> (4 - bit_offset)) & 0xF
                    else:
                        digit = x[byte_idx] & 0xF
                else:
                    digit = 0
            else:
                digit = 0
            out.append(digit)
        return out

    # ----- WOTS+ -----
    def chain(self, x: bytes, start: int, steps: int) -> bytes:
        tmp = x
        for i in range(steps):
            tmp = self.hash_f(tmp + (start + i).to_bytes(4, 'big'))
        return tmp

    def wots_gen_sk(self, sk_seed: bytes, addr: int) -> List[bytes]:
        return [self.hash_prf(sk_seed, (addr+i).to_bytes(8,'big')) for i in range(self.len)]

    def wots_gen_pk(self, sk: List[bytes]) -> bytes:
        return self.hash_f(b''.join([self.chain(sk_i, 0, self.w-1) for sk_i in sk]))

    def wots_sign(self, msg_hash: bytes, sk: List[bytes]) -> List[bytes]:
        if len(msg_hash)<32: msg_hash += b'\x00'*(32-len(msg_hash))
        msg_w = self.to_base_w(msg_hash, self.len_1)
        csum = sum(self.w-1 - m for m in msg_w)
        csum_w = self.to_base_w(csum.to_bytes(3,'big'), self.len_2)
        full_msg = msg_w + csum_w
        return [self.chain(sk[i], 0, full_msg[i]) for i in range(len(full_msg))]

    def wots_verify(self, sig: List[bytes], msg_hash: bytes) -> bytes:
        if len(msg_hash)<32: msg_hash += b'\x00'*(32-len(msg_hash))
        msg_w = self.to_base_w(msg_hash, self.len_1)
        csum = sum(self.w-1 - m for m in msg_w)
        csum_w = self.to_base_w(csum.to_bytes(3,'big'), self.len_2)
        full_msg = msg_w + csum_w
        return self.hash_f(b''.join([self.chain(sig[i], full_msg[i], self.w-1-full_msg[i]) for i in range(len(full_msg))]))

    # ----- FORS -----
    def fors_gen_sk(self, sk_seed: bytes, addr: int) -> List[bytes]:
        return [self.hash_prf(sk_seed, (addr+i).to_bytes(8,'big')) for i in range(self.k*(2**self.t))]

    def fors_sign(self, msg_indices: List[int], sk: List[bytes]) -> List[Tuple[bytes,List[bytes]]]:
        sig=[]
        for tree_idx, leaf_idx in enumerate(msg_indices):
            sk_offset = tree_idx*(2**self.t)
            leaf_sk = sk[sk_offset+leaf_idx]
            auth_path = [sk[(sk_offset+leaf_idx+level+1000)%len(sk)] for level in range(self.t)]
            sig.append((leaf_sk, auth_path))
        return sig

    def fors_verify(self, sig: List[Tuple[bytes,List[bytes]]], msg_indices: List[int]) -> bytes:
        roots=[]
        for i,(leaf_val,auth_path) in enumerate(sig):
            current=self.hash_f(leaf_val)
            for level,sibling in enumerate(auth_path):
                if (msg_indices[i]>>level)&1: current=self.hash_h(sibling,current)
                else: current=self.hash_h(current,sibling)
            roots.append(current)
        return self.hash_f(b''.join(roots))

    # ----- Clés -----
    def gen_keypair(self)->Tuple[bytes,bytes]:
        sk_seed=secrets.token_bytes(self.n)
        sk_prf=secrets.token_bytes(self.n)
        pk_seed=secrets.token_bytes(self.n)
        sk=sk_seed+sk_prf+pk_seed
        wots_sk=self.wots_gen_sk(sk_seed,0)
        wots_pk=self.wots_gen_pk(wots_sk)
        pk=wots_pk+pk_seed
        return sk, pk

    # ----- Signature -----
    def sign(self,msg:bytes,sk:bytes)->bytes:
        sk_seed,sk_prf,pk_seed=sk[:self.n],sk[self.n:2*self.n],sk[2*self.n:]
        r=self.hash_prf(sk_prf,msg)
        msg_hash=self.hash_f(r+msg)
        msg_indices=[msg_hash[i]%(2**self.t) for i in range(self.k)]

        fors_sk=self.fors_gen_sk(sk_seed,1000)
        fors_sig=self.fors_sign(msg_indices,fors_sk)
        fors_root=self.fors_verify(fors_sig,msg_indices)

        wots_sk=self.wots_gen_sk(sk_seed,0)
        wots_sig=self.wots_sign(fors_root,wots_sk)

        sig=r
        # FORS
        for leaf_sk,auth_path in fors_sig:
            sig+=leaf_sk
            for node in auth_path: sig+=node
        # WOTS+
        for part in wots_sig: sig+=part
        # Hypertree : ajouter 1 nœud par couche pour la signature (simplifié)
        for layer in range(self.d):
            # On simule un nœud par couche
            sig+=self.hash_f((r + layer.to_bytes(1,'big')))

        return sig
    

    # ----- Vérification -----
    def verify(self,sig:bytes,msg:bytes,pk:bytes)->bool:
        try:
            pk_wots,pk_seed=pk[:self.n],pk[self.n:]
            pos=0
            r=sig[pos:pos+self.n]; pos+=self.n
            msg_hash=self.hash_f(r+msg)
            msg_indices=[msg_hash[i]%(2**self.t) for i in range(self.k)]

            fors_sig=[]
            for i in range(self.k):
                leaf_sk=sig[pos:pos+self.n]; pos+=self.n
                auth_path=[sig[pos+j*self.n:pos+(j+1)*self.n] for j in range(self.t)]
                pos+=self.t*self.n
                fors_sig.append((leaf_sk,auth_path))
            fors_root=self.fors_verify(fors_sig,msg_indices)

            wots_sig=[sig[pos+i*self.n:pos+(i+1)*self.n] for i in range(self.len)]
            pos+=self.len*self.n
            # Skip hypertree nodes
            hypertree_nodes = [sig[pos+i*self.n:pos+(i+1)*self.n] for i in range(self.d)]

            computed_pk=self.wots_verify(wots_sig,fors_root)
            return computed_pk==pk_wots
        except Exception as e:
            print(f"Erreur de vérification : {e}")
            return False


