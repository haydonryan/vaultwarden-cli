use anyhow::{Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, PartialEq, Eq)]
struct TotpConfig {
    secret: Vec<u8>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
    steam: bool,
}

pub(crate) fn generate(seed: &str, timestamp: u64) -> Result<String> {
    let config = parse(seed)?;
    generate_config(&config, timestamp)
}

fn parse(seed: &str) -> Result<TotpConfig> {
    let seed = seed.trim();
    if seed
        .get(..10)
        .is_some_and(|s| s.eq_ignore_ascii_case("otpauth://"))
    {
        parse_otpauth(seed)
    } else if seed
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("steam://"))
    {
        let secret = seed.get(8..).unwrap_or_default();
        Ok(TotpConfig {
            secret: decode_base32(secret)?,
            algorithm: Algorithm::Sha1,
            digits: 5,
            period: 30,
            steam: true,
        })
    } else {
        Ok(TotpConfig {
            secret: decode_base32(seed)?,
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            steam: false,
        })
    }
}

fn parse_otpauth(uri: &str) -> Result<TotpConfig> {
    let rest = uri.get(10..).context("Invalid otpauth URI")?;
    let (path, query) = rest
        .split_once('?')
        .context("otpauth URI has no parameters")?;
    let kind = path.split('/').next().unwrap_or_default();
    if !kind.eq_ignore_ascii_case("totp") {
        anyhow::bail!("Only TOTP otpauth URIs are supported");
    }

    let mut secret = None;
    let mut algorithm = Algorithm::Sha1;
    let mut digits = 6;
    let mut period = 30;
    for parameter in query.split('&') {
        let (raw_name, raw_value) = parameter.split_once('=').unwrap_or((parameter, ""));
        let name = percent_decode(raw_name)?;
        let value = percent_decode(raw_value)?;
        match name.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(decode_base32(value.trim())?),
            "algorithm" => {
                algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => Algorithm::Sha1,
                };
            }
            "digits" => {
                digits = match value.trim().parse::<u32>() {
                    Ok(parsed) if parsed > 10 => 10,
                    Ok(parsed) if parsed > 0 => parsed,
                    _ => 6,
                };
            }
            "period" => {
                period = value
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .filter(|parsed| *parsed > 0)
                    .unwrap_or(30);
            }
            _ => {}
        }
    }

    Ok(TotpConfig {
        secret: secret.context("otpauth URI has no secret")?,
        algorithm,
        digits,
        period,
        steam: false,
    })
}

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = bytes
                    .get(index + 1)
                    .and_then(|byte| hex_value(*byte))
                    .context("Invalid percent encoding in otpauth URI")?;
                let low = bytes
                    .get(index + 2)
                    .and_then(|byte| hex_value(*byte))
                    .context("Invalid percent encoding in otpauth URI")?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).context("otpauth URI parameters are not valid UTF-8")
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_base32(value: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;

    for byte in value.bytes() {
        let digit = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => continue,
        };
        accumulator = (accumulator << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1_u32 << bits).wrapping_sub(1);
        }
    }

    if output.is_empty() {
        anyhow::bail!("Invalid Base32 TOTP secret");
    }
    Ok(output)
}

fn generate_config(config: &TotpConfig, timestamp: u64) -> Result<String> {
    let counter = timestamp
        .checked_div(config.period)
        .context("TOTP period must be positive")?
        .to_be_bytes();
    let digest = match config.algorithm {
        Algorithm::Sha1 => hmac::<Sha1>(&config.secret, &counter)?,
        Algorithm::Sha256 => hmac::<Sha256>(&config.secret, &counter)?,
        Algorithm::Sha512 => hmac::<Sha512>(&config.secret, &counter)?,
    };
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let code = u32::from_be_bytes(
        digest[offset..offset + 4]
            .try_into()
            .context("Invalid TOTP digest")?,
    ) & 0x7fff_ffff;

    if config.steam {
        let mut value = code;
        let mut output = String::with_capacity(5);
        for _ in 0..5 {
            output.push(char::from(
                STEAM_ALPHABET[value as usize % STEAM_ALPHABET.len()],
            ));
            value /= STEAM_ALPHABET.len() as u32;
        }
        return Ok(output);
    }

    let modulus = 10_u64
        .checked_pow(config.digits)
        .context("TOTP digits are too large")?;
    Ok(format!(
        "{:0width$}",
        u64::from(code) % modulus,
        width = config.digits as usize
    ))
}

fn hmac<D>(secret: &[u8], counter: &[u8]) -> Result<Vec<u8>>
where
    D: hmac::digest::block_api::EagerHash,
{
    let mut mac = Hmac::<D>::new_from_slice(secret)
        .map_err(|e| anyhow::anyhow!("Invalid TOTP secret: {e}"))?;
    mac.update(counter);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn bare_base32_uses_standard_defaults() {
        let config = parse(SHA1_SECRET).unwrap();

        assert_eq!(config.algorithm, Algorithm::Sha1);
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
        assert_eq!(generate_config(&config, 59).unwrap(), "287082");
    }

    #[test]
    fn formatted_base32_ignores_non_alphabet_characters() {
        let formatted = "GEZD-GNBV GY3T.QOJQ/GEZDGNBVGY3TQOJQ==";

        assert_eq!(generate(formatted, 59).unwrap(), "287082");
    }

    #[test]
    fn otpauth_supports_algorithms_digits_period_and_percent_encoding() {
        let sha1 = parse(&format!(
            "otpauth://totp/Test?secret={SHA1_SECRET}&algorithm=SHA1&digits=8&period=30"
        ))
        .unwrap();
        assert_eq!(generate_config(&sha1, 59).unwrap(), "94287082");

        let sha256 = parse("otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA%3D%3D%3D%3D&algorithm=SHA256&digits=8") // secrets-ignore: RFC 6238 public test vector
            .unwrap();
        assert_eq!(generate_config(&sha256, 59).unwrap(), "46119246");

        let sha512 = parse("otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA%3D&algorithm=sha512&digits=8") // secrets-ignore: RFC 6238 public test vector
            .unwrap();
        assert_eq!(generate_config(&sha512, 59).unwrap(), "90693936");

        let custom_period = parse(&format!(
            "otpauth://totp/Test?secret={SHA1_SECRET}&period=60"
        ))
        .unwrap();
        assert_eq!(generate_config(&custom_period, 59).unwrap(), "755224");
    }

    #[test]
    fn steam_uses_steam_alphabet_and_length() {
        assert_eq!(
            generate(&format!("steam://{SHA1_SECRET}"), 59).unwrap(),
            "PV9M4"
        );
        assert_eq!(
            generate("steam://GEZD-GNBV GY3T.QOJQ/GEZDGNBVGY3TQOJQ==", 59).unwrap(),
            "PV9M4"
        );
    }

    #[test]
    fn percent_decoding_preserves_literal_plus() {
        assert_eq!(percent_decode("A+B%2BC").unwrap(), "A+B+C");
    }

    #[test]
    fn invalid_totp_parameters_use_bitwarden_defaults_and_clamps() {
        for uri in [
            format!("otpauth://totp/Test?secret={SHA1_SECRET}&period=0"),
            format!("otpauth://totp/Test?secret={SHA1_SECRET}&period=invalid"),
        ] {
            assert_eq!(parse(&uri).unwrap().period, 30);
        }

        for uri in [
            format!("otpauth://totp/Test?secret={SHA1_SECRET}&digits=0"),
            format!("otpauth://totp/Test?secret={SHA1_SECRET}&digits=invalid"),
        ] {
            assert_eq!(parse(&uri).unwrap().digits, 6);
        }
        assert_eq!(
            parse(&format!(
                "otpauth://totp/Test?secret={SHA1_SECRET}&digits=20"
            ))
            .unwrap()
            .digits,
            10
        );
        assert_eq!(
            parse(&format!(
                "otpauth://totp/Test?secret={SHA1_SECRET}&algorithm=MD5"
            ))
            .unwrap()
            .algorithm,
            Algorithm::Sha1
        );
    }

    #[test]
    fn non_totp_otpauth_uri_is_rejected() {
        let error = parse(&format!(
            "otpauth://hotp/Test?secret={SHA1_SECRET}&counter=1"
        ))
        .unwrap_err()
        .to_string();

        assert!(error.contains("Only TOTP"));
    }

    #[test]
    fn invalid_secret_errors_do_not_include_the_seed() {
        let invalid_seed = "0189-+/=";
        let error = generate(invalid_seed, 59).unwrap_err().to_string();
        assert!(!error.contains(invalid_seed));
    }
}
