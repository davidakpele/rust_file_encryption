use aes::Aes256;
use argon2::Argon2;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn main() {
    fs::create_dir_all("files").expect("create files folder");
    splash();

    loop {
        println!("\nOptions:\n1. Encrypt data\n2. Decrypt data\n3. Exit");
        let mut opt = String::new();
        std::io::stdin().read_line(&mut opt).unwrap();
        match opt.trim() {
            "1" => encrypt(),
            "2" => decrypt(),
            "3" => break,
            _   => println!("Invalid option."),
        }
    }
}

/*  ENCRYPT */

fn encrypt() {
    //  file path 
    let mut name = String::new();
    println!("File to encrypt:");
    std::io::stdin().read_line(&mut name).unwrap();
    let name = name.trim();
    let plain = File::open(name).expect("open file");

    //  duration string 
    let mut dstr = String::new();
    println!("Self?destruct after (e.g. 30s, 20m, 4h, 2d):");
    std::io::stdin().read_line(&mut dstr).unwrap();
    let life = parse_duration(dstr.trim());

    //  password 
    let mut pwd = String::new();
    println!("Password:");
    std::io::stdin().read_line(&mut pwd).unwrap();
    let pwd = pwd.trim();

    //  crypto material 
    let mut salt = [0u8; 16];
    let mut iv   = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);
    let key = derive_key(pwd, &salt);

    //  read plaintext 
    let mut data = Vec::new();
    let mut f_in = plain;
    f_in.read_to_end(&mut data).unwrap();

    // encrypt
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let cipher_text = cipher.encrypt_vec(&data);

    // write header + ciphertext 
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        + life;
    let enc_path = format!("files/{}.enc", Path::new(name).file_name().unwrap().to_string_lossy());
    let mut f_out = File::create(&enc_path).unwrap();
    f_out.write_all(&salt).unwrap();
    f_out.write_all(&iv).unwrap();
    f_out.write_u64::<BigEndian>(expiry.as_secs()).unwrap(); 
    f_out.write_all(&cipher_text).unwrap();
    println!("? Saved as `{}` ¨C self?destructs in {:?}", enc_path, life);

    // background shredder 
    let gone = Arc::new(AtomicBool::new(true));
    let flag = gone.clone();
    thread::spawn(move || {
        thread::sleep(life);
        if flag.load(Ordering::SeqCst) {
            println!("\n[!] Deadline hit ¨C file corruption {}", enc_path);
            secure_corrupt(&enc_path);
        }
    });

    // optional timer cancel
    println!("Enter password again within this session to cancel timer:");
    let mut try_pwd = String::new();
    std::io::stdin().read_line(&mut try_pwd).unwrap();
    if derive_key(try_pwd.trim(), &salt) == key {
        gone.store(false, Ordering::SeqCst);
        println!("? Timer cancelled for this file.");
    } else {
        println!("Wrong password ¨C timer running.");
    }
}

/* DECRYPT */

fn decrypt() {
    // ¡ª¡ª which file? ¡ª¡ª
    let mut name = String::new();
    println!("File name (without .enc):");
    std::io::stdin().read_line(&mut name).unwrap();
    let name = name.trim();
    let path = format!("files/{}.enc", name);
    if !Path::new(&path).exists() {
        println!("? File not found in 'files/'.");
        return;
    }

    loop {
        // read header every loop in case file is erased meanwhile 
        let mut f = match File::open(&path) {
            Ok(file) => file,
            Err(_) => {
                println!("File already deleted.");
                return;
            }
        };
        let mut salt = [0u8; 16];
        let mut iv   = [0u8; 16];
        f.read_exact(&mut salt).unwrap();
        f.read_exact(&mut iv).unwrap();
        let expiry_secs = f.read_u64::<BigEndian>().unwrap();
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now_secs >= expiry_secs {
            println!("\n[!] Deadline passed ¨C erasing file.");
            secure_corrupt(&path);
            return;
        }
        let remaining = expiry_secs - now_secs;
        print_time_left(remaining);

        // password prompt 
        let mut pwd = String::new();
        println!("Password:");
        std::io::stdin().read_line(&mut pwd).unwrap();
        let key = derive_key(pwd.trim(), &salt);
        let mut ciphertext = Vec::new();
        f.read_to_end(&mut ciphertext).unwrap();
        if let Ok(cbc) = Aes256Cbc::new_from_slices(&key, &iv) {
            if let Ok(plain) = cbc.decrypt_vec(&ciphertext) {
                let out_path = format!("files/{}.dec", name);
                let mut out = File::create(&out_path).unwrap();
                out.write_all(&plain).unwrap();
                println!("? Decrypted to `{}`", out_path);
                return;
            }
        }
        println!("? Wrong password ¨C try again.");
    }
}


fn splash() {
    println!(r#"
    /^\/^\
  _|__|  O|
\/     /~     \_/ \
\____|__________/  \
 \_______      \
         `\     \                 \
           |     |                  \
          /      /                    \
         /     /                       \
       /      /                         \ \
      /     /                            \  \
    /     /             _----_            \   \
   |     |           _-~      ~-_         |   |
   |     |        _-~    _--_    ~-_     _/   |
    \____/       ~     ~\##/~~        ~~    /
     / \             _-~|##|~-_             /
    |  |           /   \  \/    \           /
    |  \          |     |       |          /
     \  \         |     |       |         /
       \ \        \_____/______/        /
        \ \           |||             /
         \_\_________///_____________/
          `----------'
"#);

    thread::sleep(Duration::from_secs(2));
}

fn show_file_corrupted_art() {
    println!(r#"
     _________
    /         \\
   /  CORRUPT  \\
   \    FILE   /
    \_________/
     /       \\
    |  x   x  |     💀
    |    ^    |    FILE CORRUPTED!
    |  \___/  |
    |_________|

    The file is no longer accessible.
    It may have been deleted, tampered with,
    or the password is incorrect.
    "#);
    thread::sleep(Duration::from_secs(2));
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("argon2 failed");
    key
}

fn parse_duration(s: &str) -> Duration {
    let (num, unit) = s.split_at(s.len() - 1);
    let n: u64 = num.parse().unwrap_or(0);
    match unit {
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n * 60),
        "h" => Duration::from_secs(n * 3600),
        "d" => Duration::from_secs(n * 86_400),
        _   => Duration::from_secs(n),
    }
}

fn print_time_left(sec: u64) {
    let (d, r1) = (sec / 86_400, sec % 86_400);
    let (h, r2) = (r1 / 3600, r1 % 3600);
    let (m, s)  = (r2 / 60,  r2 % 60);
    println!(
        "? Remaining: {}d {:02}h {:02}m {:02}s",
        d, h, m, s
    );
}

fn secure_corrupt(p: &str) {
    if !Path::new(p).exists() { return; }
    let mut file = OpenOptions::new().write(true).open(p).unwrap();
    let size = file.metadata().unwrap().len();

    file.seek(SeekFrom::Start(40)).unwrap();
    let corrupt_leg = size.saturating_sub(40);
    
    let junk: Vec<u8> = (0..corrupt_leg).map(|_| rand::random::<u8>()).collect();
    file.write_all(&junk).unwrap();
    file.flush().unwrap();

    show_file_corrupted_art();
    
}

