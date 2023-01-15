use std::fs;
use std::fs::File;
use num::bigint::Sign;
use num_bigint::BigInt;
use bytes::Bytes;
use std::env;
use std::process;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use hex;
//use block_modes::Cbc;
//use block_modes::BlockMode;//, Cbc};
//use block_modes::block_padding::Pkcs7;
use aes::cipher::block_padding::Pkcs7;
//use aes::Aes256;
use generic_array::GenericArray;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use aes::cipher::KeyIvInit;
use aes::cipher::BlockDecryptMut;

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
    println!("Hello from dump");
    let payload = Vec::new();
    let version = decrypt(fware, payload);
    println!("{}", version);//, payload.len());
}

//fn decrypt(fware: String, payload: Vec<u8>) -> (&'static[u8], u32){
fn decrypt(fware: String, mut payload: Vec<u8>) -> u32 {
    println!("Hello from decrypt");

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
    let pkcs1_rsa_sha256_id = Bytes::from_static(&[ 0x30, 0x31, 0x30, 0x0d,
                                                    0x06, 0x09, 0x60, 0x86, 
                                                    0x48, 0x01, 0x65, 0x03, 
                                                    0x04, 0x02, 0x01, 0x05, 
                                                    0x00, 0x04, 0x20 ]);
    let mut f = File::open(&fware).expect("Failed to open firmware");
    let fsize = fs::metadata(&fware).unwrap().len();
    println!("Firmware size: {}",fsize);
    let mut magic = [0u8; 4];
    let mut product = [0u8; 4];
    let mut version = [0u8; 4];
    let mut hdr_size = [0u8; 4];
    f.read(&mut magic);
    f.read(&mut product);
    f.read(&mut version);
    f.read(&mut hdr_size);
    assert!(u32::from_le_bytes(magic) == 0x50cd50cd, "Not valid firmware magic {}", u32::from_le_bytes(magic));
    assert!(u32::from_le_bytes(product) == 0x010000a5, "Not valid product {}", u32::from_le_bytes(product));
    assert!(u32::from_le_bytes(hdr_size) >= 16, "Header size less than 16 {}", u32::from_le_bytes(hdr_size));
    println!("Version: {}", u32::from_le_bytes(version));
    println!("hdr_size: {}", u32::from_le_bytes(hdr_size));
    f.seek(SeekFrom::Start(u32::from_ne_bytes(hdr_size).into()));
    let mut params_size = [0u8; 4];
    f.read(&mut params_size);
    println!("params_size: {}",u32::from_be_bytes(params_size));
    //let mut encrypted_params = Vec::with_capacity(u32::from_be_bytes(params_size).try_into().unwrap());
    let mut encrypted_sz = vec![0; u32::from_be_bytes(params_size) as usize];
    println!("encrypted_sz.len() {}",encrypted_sz.len());
    f.read(&mut encrypted_sz);
    let encrypted_params = BigInt::from_bytes_be(Sign::Plus, &encrypted_sz);
    println!("{}", encrypted_params);
    println!("Decrypting params");
    let raw_params_blob = encrypted_params.modpow(&pubkey_e, &pubkey_n).to_str_radix(16);
    let raw_params = hex::decode(&raw_params_blob[raw_params_blob.len() - ( 88 * 2) .. raw_params_blob.len()]).unwrap();
    assert!(88 == raw_params.len());
    let aes256_key = &raw_params[0..32];
    let aes256_iv = &raw_params[32..48];
    let hmac_key = &raw_params[48..80];
    let raw_params_version = &raw_params[80..84];
    assert!(raw_params_version == version);
    // remember: params_size is BIG ENDIAN
    let enc_payload_sz = fsize as usize - (4 as usize + u32::from_le_bytes(hdr_size) as usize + u32::from_be_bytes(params_size) as usize) - pubkey_n_raw.len() as usize;
    let mut encrypted_payload = vec![0u8; enc_payload_sz as usize];
    f.read(&mut encrypted_payload);
    assert!(encrypted_payload.len() == enc_payload_sz,"actual {} != calculated {}", encrypted_payload.len(), enc_payload_sz);
    let mut raw_signature = Vec::new();
    println!("{}",raw_signature.len()); // 0 - as it should be ...
    //let old_position = f.seek(SeekFrom::Current(0)).unwrap();
    //println!("old pos: {}/{}", old_position, fsize);
    f.read_to_end(&mut raw_signature);
    assert!(raw_signature.len() == pubkey_n_raw.len(), "{}/{}/256 {}", raw_signature.len(), pubkey_n_raw.len(), fsize - encrypted_payload.len()as u64);
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
    let key = GenericArray::from_slice(aes256_key);
    let iv =  GenericArray::from_slice(aes256_iv);
    //let enc_payload: GenericArray<u8, foo> = GenericArray::from_slice(&encrypted_payload);
    let mut buf = vec![0u8; enc_payload_sz];
    //type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    //let cipher = Aes256Cbc::new_var(&aes256_key, &aes256_iv).unwrap();
    //let payload = cipher.decrypt_vec(&encrypted_payload).unwrap();
    println!("{} {}", encrypted_payload.len(), encrypted_payload.len() % 16);
    let cipher = Aes256CbcDec::new(&key, &iv);
    println!("{:#?}", cipher);
    cipher.decrypt_padded_b2b_mut::<Pkcs7>(encrypted_payload.as_slice(), &mut payload).unwrap(); // UnpadError
    //let foo = cipher.decrypt_blocks_b2b_mut(&encrypted_payload, &mut buf.into_boxed_slice());//.unwrap();//.to_vec(); // UnpadError
    //let foo = cipher.decrypt_padded_vec_mut(&encrypted_payload, &mut buf.into_boxed_slice());//.unwrap();//.to_vec(); // UnpadError
    /*
        unused_space_in_last_block = payload[-1]
        block_size = 16
        assert unused_space_in_last_block <= block_size
        payload = payload[:-unused_space_in_last_block]

        signature = int.from_bytes(raw_signature, byteorder="big")
        verify_signature(payload, signature, hmac_key)

        return version, payload
*/
    verify_signature(&payload, &raw_signature, hmac_key);
    return u32::from_be_bytes(version);
}
fn verify_signature(data: &[u8], encrypted_sig: &[u8], key: &[u8]) {
    println!("Hello from verify");
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    println!("{:#?} {}", digest, digest.len());
}
    /*
    def verify_signature(data, encrypted_signature, key):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    digest = h.finalize()

    padding_needed = len(pubkey_n_raw) - (3 + len(pkcs1_rsa_sha256_id) + len(digest))
    wrapped_digest = bytearray([ 0x00, 0x01 ]) \
            + (padding_needed * bytearray([ 0xff ])) \
            + bytearray([ 0x00 ]) \
            + pkcs1_rsa_sha256_id \
            + digest
    expected_signature = int.from_bytes(wrapped_digest, byteorder="big")
    signature = pow(encrypted_signature, pubkey_e, pubkey_n)
    assert signature == expected_signature
*/
    /*
def dump(firmware, output_dir):
    version, payload = decrypt(firmware)

    cursor = io.BytesIO(payload)

    product, version_again, num_operations, header_size = struct.unpack("<IIII", cursor.read(16))
    assert product == 0x010000a5
    assert version_again == version
    cursor.seek(header_size)

    print(f"Firmware update has {num_operations} operations:")

    for i in range(num_operations):
        op_size, raw_op_type, op_arg, op_path_size, op_extra_size = struct.unpack("<IIIII", cursor.read(20))
        op_type = OperationType(raw_op_type)
        op_path = cursor.read(op_path_size).decode("utf-8")[:-1]

        alignment_remainder = op_path_size % 4
        if alignment_remainder != 0:
            alignment_padding = 4 - alignment_remainder
            cursor.seek(alignment_padding, os.SEEK_CUR)
        else:
            alignment_padding = 0

        op_data = cursor.read(op_size - (20 + op_path_size + alignment_padding + op_extra_size))

        print(f"\t{op_type} arg={op_arg} path=\"{op_path}\"")

        if op_type is OperationType.UPDATE_FILE:
            h = hashes.Hash(hashes.SHA256())
            h.update(op_data)
            digest = h.finalize().hex()
            print(f"\t\tdata=({len(op_data)} bytes, SHA-256: {digest})")

            if output_dir is not None:
                target_path = output_dir / op_path[1:]
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(op_data)
                print("\t\twritten to:", target_path)

        op_extra_data = cursor.read(op_extra_size)

    assert len(cursor.read()) == 0
*/
