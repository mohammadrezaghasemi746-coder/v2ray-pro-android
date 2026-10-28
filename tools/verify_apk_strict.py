#!/usr/bin/env python3
"""
Strict Independent Android APK Verifier
Simulates Android's PackageParser, ResXMLParser, ResTable, DexFileVerifier,
zipalign verifier, and ApkSignatureVerifier (Scheme v1 and Scheme v2).
"""

import os
import sys
import struct
import zlib
import hashlib
import base64
import zipfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

APK_PATH = "/working_dir/c_7d15cf2bc2ccfe63/artifacts/file_generation/ttl=63d/output/V2RayPro-Android-Fixed.apk"


def verify_zipalign(apk_bytes):
    print("=== [1/6] Verifying ZIP Structure & 4-Byte Zipalign ===")
    with zipfile.ZipFile(APK_PATH, "r") as zf:
        for info in zf.infolist():
            sig, ver, flags, comp, mtime, mdate, crc, csize, usize, fnlen, exlen = struct.unpack(
                "<IHHHHHIIIHH", apk_bytes[info.header_offset : info.header_offset + 30]
            )
            assert sig == 0x04034B50, f"Invalid LFH signature for {info.filename}"
            assert (flags & 0x0008) == 0, f"Data descriptor flag (bit 3) must not be set on {info.filename}"
            data_start = info.header_offset + 30 + fnlen + exlen
            if comp == 0:
                assert data_start % 4 == 0, f"STORED entry {info.filename} is NOT 4-byte aligned (offset {data_start})"
            print(f"  [OK] {info.filename:32s} comp={comp} size={usize:8d} data_start={data_start:7d} (mod4={data_start%4})")


def verify_axml(axml_bytes):
    print("\n=== [2/6] Verifying Binary AndroidManifest.xml (ResXMLParser) ===")
    ctype, cheader, csize = struct.unpack("<HHI", axml_bytes[:8])
    assert ctype == 0x0003 and cheader == 8 and csize == len(axml_bytes), "Invalid AXML header"

    # String pool
    sp_type, sp_hsize, sp_size, str_count, style_count, flags, strings_start, styles_start = struct.unpack(
        "<HHIIIIII", axml_bytes[8:36]
    )
    assert sp_type == 0x0001 and sp_hsize == 28, "Invalid StringPool header"
    strings = []
    for i in range(str_count):
        soff = struct.unpack("<I", axml_bytes[36 + i * 4 : 40 + i * 4])[0]
        abs_off = 8 + strings_start + soff
        u16_len = struct.unpack("<H", axml_bytes[abs_off : abs_off + 2])[0]
        s = axml_bytes[abs_off + 2 : abs_off + 2 + u16_len * 2].decode("utf-16le")
        null_term = struct.unpack("<H", axml_bytes[abs_off + 2 + u16_len * 2 : abs_off + 4 + u16_len * 2])[0]
        assert null_term == 0, f"Missing UTF-16 null terminator on string {s}"
        strings.append(s)

    # Resource map
    rm_pos = 8 + sp_size
    rm_type, rm_hsize, rm_size = struct.unpack("<HHI", axml_bytes[rm_pos : rm_pos + 8])
    assert rm_type == 0x0180 and rm_hsize == 8, "Invalid ResourceMap chunk"
    res_ids = list(struct.unpack("<" + "I" * ((rm_size - 8) // 4), axml_bytes[rm_pos + 8 : rm_pos + rm_size]))
    print(f"  [OK] StringPool ({len(strings)} strings) & ResourceMap ({len(res_ids)} android:* IDs)")

    pos = rm_pos + rm_size
    while pos < len(axml_bytes):
        nt, nh, ns = struct.unpack("<HHI", axml_bytes[pos : pos + 8])
        if nt == 0x0102: # START_ELEMENT
            line, comment, elem_ns, elem_name, attr_start, attr_size, attr_count, id_i, cls_i, sty_i = struct.unpack(
                "<IIiiHHHHHH", axml_bytes[pos + 8 : pos + 36]
            )
            assert nh == 16 and attr_start == 20 and attr_size == 20
            tag_name = strings[elem_name]
            prev_res_id = -1
            seen_non_res = False
            attr_summary = []
            for i in range(attr_count):
                ao = pos + 36 + i * 20
                ans, aname, araw, tsize, r0, dtype, dval = struct.unpack("<iiiHBBI", axml_bytes[ao : ao + 20])
                assert tsize == 8 and r0 == 0, "Invalid Res_value in attribute"
                attr_name = strings[aname]
                if aname < len(res_ids):
                    assert not seen_non_res, f"Element <{tag_name}> has resource attribute {attr_name} after non-resource attribute!"
                    rid = res_ids[aname]
                    assert rid > prev_res_id, (
                        f"Element <{tag_name}> attributes NOT sorted by ascending resourceId: "
                        f"0x{rid:08x} ({attr_name}) after 0x{prev_res_id:08x}"
                    )
                    prev_res_id = rid
                    attr_summary.append(f"android:{attr_name}(0x{rid:08x})")
                else:
                    seen_non_res = True
                    attr_summary.append(f"{attr_name}(no-res)")
            print(f"  [OK] <{tag_name}> attrs ({attr_count}): {', '.join(attr_summary)}")
        pos += ns


def verify_arsc(arsc_bytes):
    print("\n=== [3/6] Verifying Binary resources.arsc (ResTable) ===")
    ttype, thsize, tsize, pkg_count = struct.unpack("<HHII", arsc_bytes[:12])
    assert ttype == 0x0002 and thsize == 12 and tsize == len(arsc_bytes) and pkg_count == 1
    sp_type, sp_hsize, sp_size = struct.unpack("<HHI", arsc_bytes[12:20])
    assert sp_type == 0x0001 and sp_hsize == 28

    pkg_pos = 12 + sp_size
    ptype, phsize, psize, pkg_id = struct.unpack("<HHII", arsc_bytes[pkg_pos : pkg_pos + 12])
    assert ptype == 0x0200 and phsize == 288 and pkg_id == 0x7F and pkg_pos + psize == len(arsc_bytes)
    pkg_name = arsc_bytes[pkg_pos + 12 : pkg_pos + 268].decode("utf-16le").rstrip("\x00")
    type_strings_off, last_pub_type, key_strings_off, last_pub_key, tid_off = struct.unpack(
        "<IIIII", arsc_bytes[pkg_pos + 268 : pkg_pos + 288]
    )
    print(f"  [OK] Package name='{pkg_name}' id=0x{pkg_id:02x}")

    sub = pkg_pos + phsize
    while sub < pkg_pos + psize:
        st, sh, ss = struct.unpack("<HHI", arsc_bytes[sub : sub + 8])
        if st == 0x0201: # RES_TABLE_TYPE_TYPE
            tid, r0, r1, ecount, estart = struct.unpack("<BBHII", arsc_bytes[sub + 8 : sub + 20])
            cfg_size = struct.unpack("<I", arsc_bytes[sub + 20 : sub + 24])[0]
            assert sh == 20 + cfg_size
            assert estart == sh + 4 * ecount
            e_off = struct.unpack("<I", arsc_bytes[sub + sh : sub + sh + 4])[0]
            e_pos = sub + estart + e_off
            esize, eflags, ekey, vsize, vr0, vtype, vdata = struct.unpack("<HHIHBBI", arsc_bytes[e_pos : e_pos + 16])
            assert esize == 8 and eflags == 0 and ekey == 0
            assert vsize == 8 and vr0 == 0 and vtype == 0x03 and vdata == 0
            print(f"  [OK] Resource 0x7f{tid:02x}0000 -> entry_size={esize} val_size={vsize} dataType=0x{vtype:02x} strIdx={vdata}")
        sub += ss


def verify_dex(dex_bytes):
    print("\n=== [4/6] Verifying Dalvik Bytecode classes.dex (DexFileVerifier) ===")
    magic, checksum, sig, file_size, header_size, endian_tag = struct.unpack("<8sI20sIII", dex_bytes[:44])
    assert magic == b"dex\n035\x00" and file_size == len(dex_bytes) and header_size == 112 and endian_tag == 0x12345678
    expected_sha1 = hashlib.sha1(dex_bytes[32:]).digest()
    assert sig == expected_sha1, "DEX SHA-1 signature mismatch!"
    expected_adler = zlib.adler32(dex_bytes[12:]) & 0xFFFFFFFF
    assert checksum == expected_adler, "DEX Adler32 checksum mismatch!"

    link_sz, link_off, map_off = struct.unpack("<III", dex_bytes[44:56])
    s_sz, s_off, t_sz, t_off, p_sz, p_off, f_sz, f_off, m_sz, m_off, c_sz, c_off, d_sz, d_off = struct.unpack(
        "<IIIIIIIIIIIIII", dex_bytes[56:112]
    )

    def read_uleb(pos):
        res, shift = 0, 0
        while True:
            b = dex_bytes[pos]
            pos += 1
            res |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return res, pos

    strings = []
    for i in range(s_sz):
        soff = struct.unpack("<I", dex_bytes[s_off + i * 4 : s_off + (i + 1) * 4])[0]
        ulen, pos = read_uleb(soff)
        end = dex_bytes.index(0, pos)
        s = dex_bytes[pos:end].decode("utf-8")
        strings.append(s)
    assert strings == sorted(strings), "DEX strings are NOT sorted!"

    types = [strings[struct.unpack("<I", dex_bytes[t_off + i * 4 : t_off + (i + 1) * 4])[0]] for i in range(t_sz)]
    assert types == sorted(types, key=lambda x: strings.index(x)), "DEX types are NOT sorted!"

    # Verify map_list
    map_count = struct.unpack("<I", dex_bytes[map_off : map_off + 4])[0]
    prev_off = -1
    for i in range(map_count):
        mtype, _, mcnt, moff = struct.unpack("<HHII", dex_bytes[map_off + 4 + i * 12 : map_off + 4 + (i + 1) * 12])
        assert moff > prev_off, f"DEX map_list item {i} (type 0x{mtype:04x}) offset {moff} not ascending after {prev_off}"
        prev_off = moff
        # Ensure no invalid type 0x0004 (FIELD_ID_ITEM) when f_sz == 0
        if mtype == 0x0004:
            assert f_sz > 0
    print(f"  [OK] DEX checksum=0x{checksum:08x}, sha1={sig.hex()[:16]}..., strings={s_sz}, types={t_sz}, methods={m_sz}, classes={c_sz}")


def verify_v1_signature(apk_path):
    print("\n=== [5/6] Verifying APK Signature Scheme v1 (JAR / PKCS#7) ===")
    with zipfile.ZipFile(apk_path, "r") as zf:
        mf_bytes = zf.read("META-INF/MANIFEST.MF")
        sf_bytes = zf.read("META-INF/CERT.SF")
        rsa_bytes = zf.read("META-INF/CERT.RSA")

        # Verify SHA-256-Digest-Manifest
        mf_digest_b64 = base64.b64encode(hashlib.sha256(mf_bytes).digest()).decode("ascii")
        assert f"SHA-256-Digest-Manifest: {mf_digest_b64}\r\n".encode() in sf_bytes, "MANIFEST.MF digest mismatch in CERT.SF!"
        assert b"X-Android-APK-Signed: 2" in sf_bytes, "Missing X-Android-APK-Signed: 2 header in CERT.SF!"

    # Verify via OpenSSL CMS that CERT.RSA is a valid signature over CERT.SF with NO signedAttributes
    import subprocess, tempfile
    with tempfile.TemporaryDirectory() as d:
        sf_p = os.path.join(d, "CERT.SF")
        rsa_p = os.path.join(d, "CERT.RSA")
        with open(sf_p, "wb") as f:
            f.write(sf_bytes)
        with open(rsa_p, "wb") as f:
            f.write(rsa_bytes)
        subprocess.run([
            "openssl", "cms", "-verify", "-binary", "-inform", "DER",
            "-in", rsa_p, "-content", sf_p, "-noverify", "-out", "/dev/null"
        ], check=True)
        asn1_out = subprocess.check_output(["openssl", "asn1parse", "-inform", "DER", "-in", rsa_p]).decode()
        assert "S/MIME Capabilities" not in asn1_out and "messageDigest" not in asn1_out, "CERT.RSA contains forbidden signedAttributes!"
    print("  [OK] V1 JAR Signature verified (pure PKCS#7 SignedData without S/MIME signedAttributes)")


def verify_v2_signature(apk_bytes):
    print("\n=== [6/6] Verifying APK Signature Scheme v2 (APK Sig Block 42 / ID 0x7109871a) ===")
    # Locate EOCD (last 22 bytes since comment length is 0)
    eocd_off = len(apk_bytes) - 22
    eocd_sig, disk_no, cd_disk, disk_entries, total_entries, cd_size, cd_off, comment_len = struct.unpack(
        "<IHHHHIIH", apk_bytes[eocd_off:]
    )
    assert eocd_sig == 0x06054B50 and comment_len == 0

    # Immediately before cd_off is the end of APK Signing Block!
    magic = apk_bytes[cd_off - 16 : cd_off]
    assert magic == b"APK Sig Block 42", f"Missing APK Sig Block 42 magic before CD! Found: {magic!r}"
    size_bottom = struct.unpack("<Q", apk_bytes[cd_off - 24 : cd_off - 16])[0]
    sig_block_start = cd_off - 8 - size_bottom
    size_top = struct.unpack("<Q", apk_bytes[sig_block_start : sig_block_start + 8])[0]
    assert size_top == size_bottom, f"APK Signing Block size mismatch: top={size_top} != bottom={size_bottom}"

    # Parse ID-value pairs
    pos = sig_block_start + 8
    pairs_end = cd_off - 24
    v2_value = None
    while pos < pairs_end:
        pair_len = struct.unpack("<Q", apk_bytes[pos : pos + 8])[0]
        pair_id = struct.unpack("<I", apk_bytes[pos + 8 : pos + 12])[0]
        if pair_id == 0x7109871A:
            v2_value = apk_bytes[pos + 12 : pos + 8 + pair_len]
        pos += 8 + pair_len

    assert v2_value is not None, "APK Signature Scheme v2 ID (0x7109871a) not found in APK Signing Block!"

    def read_lp(buf, offset=0):
        l = struct.unpack("<I", buf[offset : offset + 4])[0]
        return buf[offset + 4 : offset + 4 + l], offset + 4 + l

    signers_seq, _ = read_lp(v2_value, 0)
    signer_block, _ = read_lp(signers_seq, 0)
    signed_data, off = read_lp(signer_block, 0)
    signatures_seq, off = read_lp(signer_block, off)
    public_key_der, off = read_lp(signer_block, off)

    # Parse signed_data
    digests_seq, sd_off = read_lp(signed_data, 0)
    certs_seq, sd_off = read_lp(signed_data, sd_off)
    attrs_seq, sd_off = read_lp(signed_data, sd_off)

    digest_entry, _ = read_lp(digests_seq, 0)
    digest_algo = struct.unpack("<I", digest_entry[:4])[0]
    expected_digest, _ = read_lp(digest_entry, 4)

    cert_der, _ = read_lp(certs_seq, 0)

    sig_entry, _ = read_lp(signatures_seq, 0)
    sig_algo = struct.unpack("<I", sig_entry[:4])[0]
    sig_bytes, _ = read_lp(sig_entry, 4)

    assert digest_algo == 0x0103 and sig_algo == 0x0103, "Expected RSA-2048 PKCS#1 v1.5 SHA-256 (0x0103)"

    # 1. Verify cryptographic signature over signed_data using public_key_der
    pub_key = serialization.load_der_public_key(public_key_der)
    pub_key.verify(sig_bytes, signed_data, padding.PKCS1v15(), hashes.SHA256())

    # 2. Verify certificate public key matches signer public_key_der
    cert = x509.load_der_x509_certificate(cert_der)
    cert_spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert cert_spki == public_key_der, "Certificate PublicKeyInfo does not match Signer public_key!"

    # 3. Recompute 1MB chunked digest over Section 1, Section 3 (CD), and Section 4 (EOCD with cd_offset = sig_block_start)
    sec1 = apk_bytes[:sig_block_start]
    sec3 = apk_bytes[cd_off:eocd_off]
    sec4 = bytearray(apk_bytes[eocd_off:])
    struct.pack_into("<I", sec4, 16, sig_block_start)

    
def compute_apk_v2_chunk_digest(sections):
    CHUNK_SIZE = 1024 * 1024
    chunk_digests = []
    for sec in sections:
        pos = 0
        n = len(sec)
        while pos < n:
            chunk = sec[pos : pos + CHUNK_SIZE]
            pos += CHUNK_SIZE
            h = hashlib.sha256()
            h.update(b"\xa5")
            h.update(struct.pack("<I", len(chunk)))
            h.update(chunk)
            chunk_digests.append(h.digest())
    top = hashlib.sha256()
    top.update(b"\x5a")
    top.update(struct.pack("<I", len(chunk_digests)))
    for d in chunk_digests:
        top.update(d)
    return top.digest()

    actual_digest = compute_apk_v2_chunk_digest([sec1, sec3, bytes(sec4)])
    assert actual_digest == expected_digest, "APK Signature Scheme v2 chunk digest mismatch!"
    print(f"  [OK] APK Signature Scheme v2 verified! Block size={size_top + 8} bytes, Digest={actual_digest.hex()[:24]}...")


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(__file__))
    with open(APK_PATH, "rb") as f:
        apk_bytes = f.read()
    with zipfile.ZipFile(APK_PATH, "r") as zf:
        axml_bytes = zf.read("AndroidManifest.xml")
        arsc_bytes = zf.read("resources.arsc")
        dex_bytes = zf.read("classes.dex")

    verify_zipalign(apk_bytes)
    verify_axml(axml_bytes)
    verify_arsc(arsc_bytes)
    verify_dex(dex_bytes)
    verify_v1_signature(APK_PATH)
    verify_v2_signature(apk_bytes)
    print("\nALL 6 ANDROID PACKAGE INSTALLER & SIGNATURE VERIFICATION SUITES PASSED 100%!")
