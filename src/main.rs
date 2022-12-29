use std::str;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use num::bigint::Sign;
use num_bigint::BigInt;
use bytes::Bytes;
use std::time::Instant;
use std::env;
use std::process;
use std::io::Read;
use std::io::Write;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Cursor;
use hex;
use sha2::Sha256;
use sha2::Digest;
use hmac::{Hmac, Mac};
use libaes::Cipher;

type HmacSha256 = Hmac<Sha256>;
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        // print a helpful message and quit
        println!("Usage: {} path/to/firmware", args[0]);
        process::exit(1);
    }
    let firmware = &args[1];
    dump(firmware.to_string());
}

fn dump(fware: String) {
    let update_file = 2;
    let (version, payload) = decrypt(fware);//, payload);
    let mut product_buf = [0u8; 4];
    let mut cursor = Cursor::new(payload);
    cursor.read(&mut product_buf).unwrap();
    let product = u32::from_le_bytes(product_buf);
    assert!(product == 0x010000a5,"fixed: {} != calculated {}", 0x010000a5, product);
    let mut v_buf = [0u8; 4];
    cursor.read(&mut v_buf).unwrap();
    let version_again = u32::from_le_bytes(v_buf);
    assert!(version == version_again, "Header Version: {} != Payload Version: {}", version, version_again);
    let mut ops_buf = [0u8; 4];
    cursor.read(&mut ops_buf).unwrap();
    let num_ops = u32::from_le_bytes(ops_buf);
    let mut hdr_buf = [0u8; 4];
    cursor.read(&mut hdr_buf).unwrap();
    let hdr_size = u32::from_le_bytes(hdr_buf);
    cursor.seek(SeekFrom::Start(hdr_size as u64)).unwrap();
    println!("Firmware update has {} operations", num_ops);
    for _i in 0..num_ops {
        let mut op_sz_buf = [0u8; 4];
        cursor.read(&mut op_sz_buf).unwrap();
        let op_size = u32::from_le_bytes(op_sz_buf);
        let mut op_type_buf = [0u8; 4];
        cursor.read(&mut op_type_buf).unwrap();
        let op_type = u32::from_le_bytes(op_type_buf);
        let mut op_arg_buf = [0u8; 4];
        cursor.read(&mut op_arg_buf).unwrap();
        let _op_arg = u32::from_le_bytes(op_arg_buf);
        let mut op_path_sz_buf = [0u8; 4];
        cursor.read(&mut op_path_sz_buf).unwrap();
        let op_path_sz = u32::from_le_bytes(op_path_sz_buf);
        let mut op_xtra_sz_buf = [0u8; 4];
        cursor.read(&mut op_xtra_sz_buf).unwrap();
        let op_xtra_sz = u32::from_le_bytes(op_xtra_sz_buf);
        let mut op_path_buf = vec![0u8; op_path_sz.try_into().unwrap()];
        cursor.read(&mut op_path_buf).unwrap();
        let s = match str::from_utf8(&mut op_path_buf) {
            Ok(v) => v,
            Err(_e) => "b00m",
        };
        let op_path = s;
        let alignment_rem = op_path_sz % 4;
        let mut alignment_padding = 0;
        if alignment_rem != 0 {
            alignment_padding = 4 - alignment_rem;
            cursor.seek(SeekFrom::Current(alignment_padding as i64)).unwrap();
        }
        let op_data_sz = op_size - 20 - op_path_sz - alignment_padding - op_xtra_sz;
        let mut op_data = vec![0u8; op_data_sz as usize];
        cursor.read(&mut op_data).unwrap();
        let mut xtra_sz = vec![0u8; op_xtra_sz as usize];
        cursor.read(&mut xtra_sz).unwrap();
        if op_type == update_file {
            let mut hasher = Sha256::new();
            let data_length = op_data.len();
            let file_data = op_data.clone();
            hasher.update(op_data);
            let digest = hasher.finalize();
            println!("{} data={} bytes, SHA-256: {}", op_path, data_length, hex::encode(digest));
            let root = Path::new("dumpdir");
            let b: bool = root.is_dir();
            if b {
                assert!(env::set_current_dir(&root).is_ok());
                // we can also add a new var and remove mut ...
                let mut dump_path = env::current_dir().unwrap();
                //println!("The current directory is {}", dump_path.display());
                let mut base_path = PathBuf::from(dump_path.clone());
                // PathBuf.push an absolute path overwrites the path ...
                base_path.push(Path::new(&op_path[1..op_path.len()])); // push-ing an abs path overwrites ...
                base_path.pop();
                fs::create_dir_all(base_path.clone()).unwrap();
                let tmp = op_path.split("/").collect::<Vec<_>>();
                let fname = tmp[tmp.len()-1];
                assert!(env::set_current_dir(base_path).is_ok());
                let mut f = File::create(fname.trim_matches(char::from(0))).unwrap();
                f.write(&file_data).unwrap();
                // cd ..
                dump_path.pop();
                assert!(env::set_current_dir(dump_path.clone()).is_ok());
                assert!(env::current_dir().unwrap() == dump_path,"{} != {}", env::current_dir().unwrap().display(), dump_path.display());
            }
        }
    }
    let mut junk = Vec::new();
    let nbytes = cursor.read_to_end(&mut junk).unwrap();
    assert!(nbytes == 0,"junk bytes found at end of file: {}", nbytes);
}

fn decrypt(fware: String) -> (u32, Vec<u8>) {
    let pubkey_n_raw = Bytes::from_static(&[
    0xd1, 0xfc, 0x8c, 0x2e, 0xce, 0xc0, 0x1e, 0x44, 0xfb, 0x49, 0x30, 0xe8, 0xc2, 0x58, 0x84, 0xaf,
    0x5c, 0xcf, 0xa4, 0x13, 0x9b, 0x75, 0x8b, 0x10, 0x1c, 0x32, 0x98, 0x74, 0x7c, 0x66, 0xb8, 0xa5,
    0x85, 0xae, 0xca, 0xa2, 0x54, 0xe4, 0x75, 0x72, 0x88, 0xa5, 0x8f, 0xdb, 0xd9, 0xfa, 0x70, 0x95,
    0xc0, 0xaf, 0xca, 0x69, 0x07, 0x8e, 0x45, 0x78, 0x96, 0xd1, 0x2a, 0xa1, 0x81, 0x5a, 0x49, 0x84,
    0xe2, 0x45, 0x46, 0xf7, 0xcf, 0x43, 0xb1, 0xe3, 0x46, 0xa3, 0x36, 0xe8, 0x38, 0xaf, 0xf5, 0xc9,
    0xff, 0x78, 0xa2, 0x0f, 0xa7, 0xc6, 0x9c, 0x4b, 0xff, 0x9c, 0xa4, 0xfd, 0x9c, 0xc0, 0xda, 0xd3,
    0x4f, 0xf1, 0x51, 0x00, 0x43, 0x88, 0xe7, 0xe0, 0x51, 0xbe, 0x2c, 0x4e, 0x5b, 0xa5, 0x31, 0x61,
    0x32, 0xb2, 0x2d, 0x2d, 0x28, 0x81, 0x63, 0x26, 0x28, 0xfb, 0x98, 0x13, 0xf0, 0x8b, 0x3f, 0xc0,
    0x53, 0x52, 0x2f, 0x5f, 0x20, 0xbc, 0x26, 0x9e, 0x48, 0x1c, 0xb8, 0x4f, 0x77, 0x54, 0x04, 0x32,
    0x62, 0x8a, 0x37, 0xbb, 0x0c, 0x49, 0xa0, 0xa0, 0x96, 0xbd, 0x54, 0xf5, 0xd4, 0x9e, 0xee, 0x03,
    0x4a, 0x8b, 0xf7, 0x0b, 0x41, 0x4b, 0x36, 0xd2, 0xeb, 0x87, 0x8c, 0x10, 0x47, 0xe5, 0x3a, 0x82,
    0x3a, 0x07, 0x70, 0xd3, 0xfc, 0x63, 0xc3, 0xd6, 0xf6, 0x03, 0x09, 0x05, 0x0c, 0x2f, 0x81, 0x9a,
    0x47, 0x50, 0x04, 0x2e, 0x80, 0x50, 0x81, 0x1f, 0xde, 0x73, 0x7e, 0x89, 0xc5, 0x1b, 0xd4, 0x5a,
    0xac, 0x47, 0x74, 0x15, 0x40, 0xe3, 0xc8, 0xf5, 0xbd, 0xce, 0x10, 0xc5, 0xb0, 0x06, 0xbc, 0x26,
    0xef, 0x74, 0x41, 0xd6, 0xd6, 0xe6, 0xa8, 0x4d, 0x76, 0xf7, 0x87, 0x5e, 0x43, 0x90, 0x6c, 0xa0,
    0x44, 0xbe, 0x0e, 0xd4, 0xad, 0xab, 0x13, 0xb1, 0x9c, 0x35, 0x2e, 0x35, 0xb9, 0xe0, 0x0b, 0x73
    ]);
    let pubkey_n  = num_bigint::BigInt::from_bytes_be(Sign::Plus, &pubkey_n_raw);
    let pubkey_e = num_bigint::BigInt::from_bytes_be(Sign::Plus, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 ]);
    let mut f = File::open(&fware).expect("Failed to open firmware");
    let fsize = fs::metadata(&fware).unwrap().len();
    println!("Firmware size: {}",fsize);
    let mut magic = [0u8; 4];
    let mut product = [0u8; 4];
    let mut version = [0u8; 4];
    let mut hdr_size = [0u8; 4];
    f.read(&mut magic).unwrap();
    f.read(&mut product).unwrap();
    f.read(&mut version).unwrap();
    f.read(&mut hdr_size).unwrap();
    assert!(u32::from_le_bytes(magic) == 0x50cd50cd, "Not valid firmware magic {}", u32::from_le_bytes(magic));
    assert!(u32::from_le_bytes(product) == 0x010000a5, "Not valid product {}", u32::from_le_bytes(product));
    assert!(u32::from_le_bytes(hdr_size) >= 16, "Header size less than 16 {}", u32::from_le_bytes(hdr_size));
    println!("Version: {}", u32::from_le_bytes(version));
    println!("hdr_size: {}", u32::from_le_bytes(hdr_size));
    f.seek(SeekFrom::Start(u32::from_ne_bytes(hdr_size).into())).unwrap();
    let mut params_size = [0u8; 4];
    f.read(&mut params_size).unwrap();
    println!("params_size: {}",u32::from_be_bytes(params_size));
    let mut encrypted_sz = vec![0; u32::from_be_bytes(params_size) as usize];
    println!("encrypted_sz.len() {}",encrypted_sz.len());
    f.read(&mut encrypted_sz).unwrap();
    let encrypted_params = BigInt::from_bytes_be(Sign::Plus, &encrypted_sz);
    let pam_before = Instant::now();
    let raw_params_blob = encrypted_params.modpow(&pubkey_e, &pubkey_n).to_str_radix(16);
    let raw_params = hex::decode(&raw_params_blob[raw_params_blob.len() - ( 88 * 2) .. raw_params_blob.len()]).unwrap();
    assert!(88 == raw_params.len());
    let pam_after = Instant::now();
    println!("Parameter Decryption took {:?}", pam_after.duration_since(pam_before));
    let aes256_key = &raw_params[0..32];
    let aes256_iv = &raw_params[32..48];
    let hmac_key = &raw_params[48..80];
    let raw_params_version = &raw_params[80..84];
    assert!(raw_params_version == version);
    // remember: params_size is BIG ENDIAN
    let enc_payload_sz = fsize as usize - (4 as usize + u32::from_le_bytes(hdr_size) as usize + u32::from_be_bytes(params_size) as usize) - pubkey_n_raw.len() as usize;
    let mut encrypted_payload = vec![0u8; enc_payload_sz as usize];
    f.read(&mut encrypted_payload).unwrap();
    assert!(encrypted_payload.len() == enc_payload_sz,"actual {} != calculated {}", encrypted_payload.len(), enc_payload_sz);
    let mut raw_signature = Vec::new();
    f.read_to_end(&mut raw_signature).unwrap();
    assert!(raw_signature.len() == pubkey_n_raw.len(), "{}/{}/256 {}", raw_signature.len(), pubkey_n_raw.len(), fsize - encrypted_payload.len()as u64);
    assert!(32 == aes256_key.len(),"invalid length for AES256 key: {}", aes256_key.len());
    let cipher = Cipher::new_256(aes256_key.try_into().unwrap());
    let before_dec = Instant::now();
    let payload = cipher.cbc_decrypt(aes256_iv.try_into().unwrap(), &encrypted_payload[..]).to_vec();
    let after_dec = Instant::now();
    println!("Payload Decryption took {:?}", after_dec.duration_since(before_dec));
    // Yeehaw - cbc_decrypt takes care of padding automatically
    let _signature  = num_bigint::BigInt::from_bytes_be(Sign::Plus, &raw_signature);
    verify_signature(&payload, &raw_signature, hmac_key, pubkey_e, pubkey_n);
    return (u32::from_le_bytes(version), payload);
}
fn verify_signature(data: &[u8], encrypted_sig: &[u8], key: &[u8], e: BigInt, n: BigInt) {
    let pkcs1_rsa_sha256_id = Bytes::from_static(&[ 0x30, 0x31, 0x30, 0x0d,
                                                    0x06, 0x09, 0x60, 0x86,
                                                    0x48, 0x01, 0x65, 0x03,
                                                    0x04, 0x02, 0x01, 0x05,
                                                    0x00, 0x04, 0x20 ]);

    let start = Instant::now();
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    let padding_needed = 256 - pkcs1_rsa_sha256_id.len() - 3 - digest.len();
    let mut wrapped = Vec::new();
    wrapped.push(0x00 as u8);
    wrapped.push(0x01 as u8);
    let mut tmp2 = vec![0xffu8; padding_needed];
    wrapped.append(&mut tmp2);
    wrapped.push(0x00 as u8);
    wrapped.append(&mut pkcs1_rsa_sha256_id.to_vec());
    wrapped.append(&mut digest.to_vec());
    let expected_sig = num_bigint::BigInt::from_bytes_be(Sign::Plus, &wrapped);
    let actual_n = num_bigint::BigInt::from_bytes_be(Sign::Plus, &encrypted_sig);
    let actual_sig = actual_n.modpow(&e, &n);
    let end = Instant::now();
    println!("Signature verification took {:?}", end.duration_since(start));
    assert!(expected_sig == actual_sig,"expected/actual signature mismatch {} != {}", expected_sig, actual_sig);
}
