use serde::{Deserialize, Deserializer, Serialize};
use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::str::FromStr;

// ── Newtype IDs ─────────────────────────────────────────────────────────────────
macro_rules! newtype_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(try_from = "String")]
        pub struct $name(String);

        impl $name {
            /// Create a new ID, validating it is non-empty.
            pub fn new(value: impl Into<String>) -> Result<Self, String> {
                let s = value.into();
                if s.is_empty() {
                    Err(format!("{} must not be empty", stringify!($name)))
                } else {
                    Ok(Self(s))
                }
            }

            /// Get the inner string value.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Convert into the inner String, consuming self.
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl Eq for $name {}

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &str {
                &self.0
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl Borrow<String> for $name {
            fn borrow(&self) -> &String {
                &self.0
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                self.0 == *other
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s.to_string())
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }
    };
}

newtype_id!(CipherId);
newtype_id!(OrgId);
newtype_id!(CollectionId);
newtype_id!(FolderId);
newtype_id!(UserId);

// ── KDF Type enum ───────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}
impl std::fmt::Display for KdfType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pbkdf2 => write!(f, "pbkdf2"),
            Self::Argon2id => write!(f, "argon2id"),
        }
    }
}
impl<'de> Deserialize<'de> for KdfType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<serde_json::Value>::deserialize(deserializer)?;
        match value {
            Some(serde_json::Value::Number(n)) => match n.as_u64() {
                Some(0) => Ok(Self::Pbkdf2),
                Some(1) => Ok(Self::Argon2id),
                _ => Err(serde::de::Error::custom(format!(
                    "unknown KdfType value: {n}"
                ))),
            },
            _ => Err(serde::de::Error::custom("expected a number for KdfType")),
        }
    }
}

// ── FieldType enum ──────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FieldType {
    Text = 0,
    Hidden = 1,
    Boolean = 2,
    Linked = 3,
}
impl FieldType {
    #[must_use]
    pub const fn is_hidden(self) -> bool {
        matches!(self, Self::Hidden)
    }
}
impl std::fmt::Display for FieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Hidden => write!(f, "hidden"),
            Self::Boolean => write!(f, "boolean"),
            Self::Linked => write!(f, "linked"),
        }
    }
}
impl<'de> Deserialize<'de> for FieldType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<serde_json::Value>::deserialize(deserializer)?;
        Ok(match value {
            Some(serde_json::Value::Number(n)) => {
                match n.as_u64().and_then(|n| u8::try_from(n).ok()) {
                    Some(0) => Self::Text,
                    Some(1) => Self::Hidden,
                    Some(2) => Self::Boolean,
                    Some(3) => Self::Linked,
                    _ => {
                        return Err(serde::de::Error::custom(format!(
                            "unknown FieldType value: {n}"
                        )));
                    }
                }
            }
            Some(serde_json::Value::String(s)) => match s.parse::<u8>() {
                Ok(0) => Self::Text,
                Ok(1) => Self::Hidden,
                Ok(2) => Self::Boolean,
                Ok(3) => Self::Linked,
                _ => {
                    return Err(serde::de::Error::custom(format!(
                        "unknown FieldType string value: {s}"
                    )));
                }
            },
            _ => {
                return Err(serde::de::Error::custom(
                    "expected a number or string for FieldType",
                ));
            }
        })
    }
}

// ── UriMatchType enum ───────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}
impl std::fmt::Display for UriMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain => write!(f, "domain"),
            Self::Host => write!(f, "host"),
            Self::StartsWith => write!(f, "starts_with"),
            Self::Exact => write!(f, "exact"),
            Self::RegularExpression => write!(f, "regex"),
            Self::Never => write!(f, "never"),
        }
    }
}
impl<'de> Deserialize<'de> for UriMatchType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<serde_json::Value>::deserialize(deserializer)?;
        match value {
            Some(serde_json::Value::Number(n)) => match n.as_u64() {
                Some(0) => Ok(Self::Domain),
                Some(1) => Ok(Self::Host),
                Some(2) => Ok(Self::StartsWith),
                Some(3) => Ok(Self::Exact),
                Some(4) => Ok(Self::RegularExpression),
                Some(5) => Ok(Self::Never),
                _ => Err(serde::de::Error::custom(format!(
                    "unknown UriMatchType value: {n}"
                ))),
            },
            Some(serde_json::Value::String(s)) => match s.parse::<u8>() {
                Ok(0) => Ok(Self::Domain),
                Ok(1) => Ok(Self::Host),
                Ok(2) => Ok(Self::StartsWith),
                Ok(3) => Ok(Self::Exact),
                Ok(4) => Ok(Self::RegularExpression),
                Ok(5) => Ok(Self::Never),
                _ => Err(serde::de::Error::custom(format!(
                    "unknown UriMatchType string value: {s}"
                ))),
            },
            _ => Err(serde::de::Error::custom(
                "expected a number or string for UriMatchType",
            )),
        }
    }
}

// OAuth2 Token Response
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    #[serde(alias = "Key", alias = "key")]
    pub key: Option<String>,
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "Kdf", alias = "kdf")]
    pub kdf: Option<KdfType>,
    #[serde(alias = "KdfIterations", alias = "kdfIterations")]
    pub kdf_iterations: Option<u32>,
}

// Sync Response - contains all vault data
#[derive(Debug, Clone, Deserialize)]
pub struct SyncResponse {
    #[serde(alias = "Ciphers", alias = "ciphers")]
    pub ciphers: Vec<Cipher>,
    #[serde(alias = "Folders", alias = "folders")]
    pub folders: Vec<Folder>,
    #[serde(alias = "Collections", alias = "collections", default)]
    pub collections: Vec<Collection>,
    #[serde(alias = "Profile", alias = "profile")]
    pub profile: Profile,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CipherListResponse {
    #[serde(alias = "Data", alias = "data", default)]
    pub data: Vec<Cipher>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Organization {
    #[serde(alias = "Id", alias = "id")]
    pub id: OrgId,
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "Key", alias = "key")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    #[serde(alias = "Id", alias = "id")]
    pub id: UserId,
    #[serde(alias = "Email", alias = "email")]
    pub email: String,
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "Key", alias = "key")]
    pub key: Option<String>,
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "Organizations", alias = "organizations", default)]
    pub organizations: Vec<Organization>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Folder {
    #[serde(alias = "Id", alias = "id")]
    pub id: FolderId,
    #[serde(alias = "Name", alias = "name")]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Collection {
    #[serde(alias = "Id", alias = "id")]
    pub id: CollectionId,
    #[serde(alias = "Name", alias = "name")]
    pub name: String,
    #[serde(alias = "OrganizationId", alias = "organizationId")]
    pub organization_id: OrgId,
}

// Cipher types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
pub enum CipherType {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
    SshKey = 5,
}

impl std::fmt::Display for CipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Login => write!(f, "login"),
            Self::SecureNote => write!(f, "note"),
            Self::Card => write!(f, "card"),
            Self::Identity => write!(f, "identity"),
            Self::SshKey => write!(f, "ssh"),
        }
    }
}
impl<'de> Deserialize<'de> for CipherType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let n = u8::deserialize(deserializer)?;
        match n {
            1 => Ok(Self::Login),
            2 => Ok(Self::SecureNote),
            3 => Ok(Self::Card),
            4 => Ok(Self::Identity),
            5 | 6 => Ok(Self::SshKey),
            _ => Err(serde::de::Error::custom("unknown cipher type value")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid cipher type")]
pub struct ParseCipherTypeError;

impl FromStr for CipherType {
    type Err = ParseCipherTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s.eq_ignore_ascii_case("login") || s == "1" => Ok(Self::Login),
            _ if s.eq_ignore_ascii_case("note")
                || s.eq_ignore_ascii_case("securenote")
                || s == "2" =>
            {
                Ok(Self::SecureNote)
            }
            _ if s.eq_ignore_ascii_case("card") || s == "3" => Ok(Self::Card),
            _ if s.eq_ignore_ascii_case("identity") || s == "4" => Ok(Self::Identity),
            _ if s.eq_ignore_ascii_case("ssh")
                || s.eq_ignore_ascii_case("sshkey")
                || s == "5"
                || s == "6" =>
            {
                Ok(Self::SshKey)
            }
            _ => Err(ParseCipherTypeError),
        }
    }
}

/// Cipher data variants — mutually exclusive.
/// Only one variant is present per cipher; the type discriminator is
/// embedded in the variant itself rather than stored as a separate field.
#[derive(Debug, Clone)]
pub enum CipherData {
    Login(LoginData),
    SecureNote(SecureNoteData),
    Card(CardData),
    Identity(IdentityData),
    SshKey(SshKeyData),
}

impl CipherData {
    /// Return the corresponding `CipherType` for this variant.
    #[must_use]
    pub fn cipher_type(&self) -> CipherType {
        match self {
            Self::Login(_) => CipherType::Login,
            Self::SecureNote(_) => CipherType::SecureNote,
            Self::Card(_) => CipherType::Card,
            Self::Identity(_) => CipherType::Identity,
            Self::SshKey(_) => CipherType::SshKey,
        }
    }
}

/// Helper to get typed data from a CipherData reference.
#[must_use]
pub fn cipher_login_data(data: &CipherData) -> Option<&LoginData> {
    if let CipherData::Login(v) = data {
        Some(v)
    } else {
        None
    }
}
#[must_use]
pub fn cipher_card_data(data: &CipherData) -> Option<&CardData> {
    if let CipherData::Card(v) = data {
        Some(v)
    } else {
        None
    }
}
#[must_use]
pub fn cipher_identity_data(data: &CipherData) -> Option<&IdentityData> {
    if let CipherData::Identity(v) = data {
        Some(v)
    } else {
        None
    }
}
#[must_use]
pub fn cipher_secure_note_data(data: &CipherData) -> Option<&SecureNoteData> {
    if let CipherData::SecureNote(v) = data {
        Some(v)
    } else {
        None
    }
}
#[must_use]
pub fn cipher_ssh_key_data(data: &CipherData) -> Option<&SshKeyData> {
    if let CipherData::SshKey(v) = data {
        Some(v)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct Cipher {
    pub id: CipherId,
    pub organization_id: Option<OrgId>,
    pub deleted_date: Option<String>,
    pub name: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<FolderId>,
    pub collection_ids: Vec<CollectionId>,
    pub fields: Option<Vec<FieldData>>,
    /// Nested cipher data (Vaultwarden alternate format).
    pub data: Option<NestedCipherData>,
    /// The exclusive cipher data variant.
    pub cipher_data: Option<CipherData>,
}

/// Custom Deserialize for Cipher: reads the flat JSON layout (Type + separate
/// Login/Card/Identity/SecureNote/SshKey fields) and constructs the CipherData enum.
impl<'de> Deserialize<'de> for Cipher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct CipherHelper {
            #[serde(alias = "Id", alias = "id")]
            id: CipherId,
            #[serde(alias = "OrganizationId", alias = "organizationId")]
            organization_id: Option<OrgId>,
            #[serde(alias = "DeletedDate", alias = "deletedDate")]
            deleted_date: Option<String>,
            #[serde(alias = "Name", alias = "name")]
            name: Option<String>,
            #[serde(alias = "Notes", alias = "notes")]
            notes: Option<String>,
            #[serde(alias = "FolderId", alias = "folderId")]
            folder_id: Option<FolderId>,
            #[serde(alias = "CollectionIds", alias = "collectionIds", default)]
            collection_ids: Vec<CollectionId>,
            #[serde(alias = "Fields", alias = "fields")]
            fields: Option<Vec<FieldData>>,
            #[serde(alias = "Data", alias = "data")]
            data: Option<NestedCipherData>,
            #[serde(rename = "Type", alias = "type")]
            r#type: CipherType,
            #[serde(alias = "Login", alias = "login")]
            login: Option<LoginData>,
            #[serde(alias = "Card", alias = "card")]
            card: Option<CardData>,
            #[serde(alias = "Identity", alias = "identity")]
            identity: Option<IdentityData>,
            #[serde(alias = "SecureNote", alias = "secureNote")]
            secure_note: Option<SecureNoteData>,
            #[serde(alias = "SshKey", alias = "sshKey")]
            ssh_key: Option<SshKeyData>,
        }

        let h = CipherHelper::deserialize(deserializer)?;
        let cipher_data = Some(match h.r#type {
            CipherType::Login => CipherData::Login(h.login.unwrap_or(LoginData {
                username: None,
                password: None,
                totp: None,
                uris: None,
            })),
            CipherType::SecureNote => {
                CipherData::SecureNote(h.secure_note.unwrap_or(SecureNoteData { r#type: None }))
            }
            CipherType::Card => CipherData::Card(h.card.unwrap_or(CardData {
                cardholder_name: None,
                brand: None,
                number: None,
                exp_month: None,
                exp_year: None,
                code: None,
            })),
            CipherType::Identity => CipherData::Identity(h.identity.unwrap_or(IdentityData {
                title: None,
                first_name: None,
                middle_name: None,
                last_name: None,
                email: None,
                phone: None,
                company: None,
            })),
            CipherType::SshKey => CipherData::SshKey(h.ssh_key.unwrap_or(SshKeyData {
                private_key: None,
                public_key: None,
                fingerprint: None,
            })),
        });
        Ok(Cipher {
            id: h.id,
            organization_id: h.organization_id,
            deleted_date: h.deleted_date,
            name: h.name,
            notes: h.notes,
            folder_id: h.folder_id,
            collection_ids: h.collection_ids,
            fields: h.fields,
            data: h.data,
            cipher_data,
        })
    }
}

// Flattened deserialization: the wire format sends `Type` + `Login`/`Card`/...
// as flat JSON keys. We use `#[serde(flatten)]` with a custom Deserialize impl
// on CipherData that reads those keys and builds the correct variant.

// Nested cipher data (Vaultwarden returns data in this nested format)
#[derive(Debug, Clone, Deserialize)]
pub struct NestedCipherData {
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "Notes", alias = "notes")]
    pub notes: Option<String>,
    #[serde(alias = "Username", alias = "username")]
    pub username: Option<String>,
    #[serde(alias = "Password", alias = "password")]
    pub password: Option<String>,
    #[serde(alias = "Totp", alias = "totp")]
    pub totp: Option<String>,
    #[serde(alias = "Uri", alias = "uri")]
    pub uri: Option<String>,
    #[serde(alias = "Uris", alias = "uris")]
    pub uris: Option<Vec<UriData>>,
    #[serde(alias = "Fields", alias = "fields")]
    pub fields: Option<Vec<FieldData>>,
}

impl Cipher {
    fn resolve_field<'a>(
        &'a self,
        direct: Option<&'a str>,
        nested: impl FnOnce(&'a NestedCipherData) -> Option<&'a str>,
    ) -> Option<&'a str> {
        direct.or_else(|| self.data.as_ref().and_then(nested))
    }

    // Get the name from either direct field or nested data
    #[must_use]
    pub fn get_name(&self) -> Option<&str> {
        self.resolve_field(self.name.as_deref(), |d| d.name.as_deref())
    }

    // Get username from cipher_data or nested data
    #[must_use]
    pub fn get_username(&self) -> Option<&str> {
        let from_data = self.cipher_data.as_ref().and_then(|cd| {
            if let CipherData::Login(login) = cd {
                login.username.as_deref()
            } else {
                None
            }
        });
        self.resolve_field(from_data, |d| d.username.as_deref())
    }

    // Get password from cipher_data or nested data
    #[must_use]
    pub fn get_password(&self) -> Option<&str> {
        let from_data = self.cipher_data.as_ref().and_then(|cd| {
            if let CipherData::Login(login) = cd {
                login.password.as_deref()
            } else {
                None
            }
        });
        self.resolve_field(from_data, |d| d.password.as_deref())
    }

    // Get URI from cipher_data or nested data
    #[must_use]
    pub fn get_uri(&self) -> Option<&str> {
        let direct = self
            .cipher_data
            .as_ref()
            .and_then(|cd| {
                if let CipherData::Login(login) = cd {
                    login.uris.as_ref()
                } else {
                    None
                }
            })
            .and_then(|uris| uris.first())
            .and_then(|u| u.uri.as_deref());
        self.resolve_field(direct, |d| {
            d.uri.as_deref().or_else(|| {
                d.uris
                    .as_ref()
                    .and_then(|uris| uris.first())
                    .and_then(|u| u.uri.as_deref())
            })
        })
    }

    // Get notes
    #[must_use]
    pub fn get_notes(&self) -> Option<&str> {
        self.resolve_field(self.notes.as_deref(), |d| d.notes.as_deref())
    }

    // Get fields
    #[must_use]
    pub fn get_fields(&self) -> Option<&Vec<FieldData>> {
        self.fields
            .as_ref()
            .or_else(|| self.data.as_ref().and_then(|d| d.fields.as_ref()))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginData {
    #[serde(alias = "Username", alias = "username")]
    pub username: Option<String>,
    #[serde(alias = "Password", alias = "password")]
    pub password: Option<String>,
    #[serde(alias = "Totp", alias = "totp")]
    pub totp: Option<String>,
    #[serde(alias = "Uris", alias = "uris")]
    pub uris: Option<Vec<UriData>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UriData {
    #[serde(alias = "Uri", alias = "uri")]
    pub uri: Option<String>,
    #[serde(alias = "Match", alias = "match")]
    pub r#match: Option<UriMatchType>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CardData {
    #[serde(alias = "CardholderName", alias = "cardholderName")]
    pub cardholder_name: Option<String>,
    #[serde(alias = "Brand", alias = "brand")]
    pub brand: Option<String>,
    #[serde(alias = "Number", alias = "number")]
    pub number: Option<String>,
    #[serde(alias = "ExpMonth", alias = "expMonth")]
    pub exp_month: Option<String>,
    #[serde(alias = "ExpYear", alias = "expYear")]
    pub exp_year: Option<String>,
    #[serde(alias = "Code", alias = "code")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityData {
    #[serde(alias = "Title", alias = "title")]
    pub title: Option<String>,
    #[serde(alias = "FirstName", alias = "firstName")]
    pub first_name: Option<String>,
    #[serde(alias = "MiddleName", alias = "middleName")]
    pub middle_name: Option<String>,
    #[serde(alias = "LastName", alias = "lastName")]
    pub last_name: Option<String>,
    #[serde(alias = "Email", alias = "email")]
    pub email: Option<String>,
    #[serde(alias = "Phone", alias = "phone")]
    pub phone: Option<String>,
    #[serde(alias = "Company", alias = "company")]
    pub company: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecureNoteData {
    #[serde(alias = "Type", alias = "type")]
    pub r#type: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SshKeyData {
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "PublicKey", alias = "publicKey")]
    pub public_key: Option<String>,
    #[serde(
        alias = "Fingerprint",
        alias = "fingerprint",
        alias = "keyFingerprint",
        alias = "KeyFingerprint"
    )]
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldData {
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "Value", alias = "value")]
    pub value: Option<String>,
    #[serde(alias = "Type", alias = "type")]
    pub r#type: FieldType,
}

// Simplified cipher output for display (decrypted)
#[derive(Debug, Clone, Serialize)]
pub struct CipherOutput {
    pub id: String,
    #[serde(rename = "type")]
    pub cipher_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<FieldOutput>>,
    // SSH key fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldOutput {
    pub name: String,
    pub value: String,
    pub hidden: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // CipherType tests
    mod cipher_type_tests {
        use super::*;

        #[test]
        fn test_cipher_type_display() {
            assert_eq!(CipherType::Login.to_string(), "login");
            assert_eq!(CipherType::SecureNote.to_string(), "note");
            assert_eq!(CipherType::Card.to_string(), "card");
            assert_eq!(CipherType::Identity.to_string(), "identity");
            assert_eq!(CipherType::SshKey.to_string(), "ssh");
        }

        #[test]
        fn test_cipher_type_from_str_login() {
            assert_eq!(CipherType::from_str("login"), Ok(CipherType::Login));
            assert_eq!(CipherType::from_str("LOGIN"), Ok(CipherType::Login));
            assert_eq!(CipherType::from_str("Login"), Ok(CipherType::Login));
            assert_eq!(CipherType::from_str("1"), Ok(CipherType::Login));
        }

        #[test]
        fn test_cipher_type_from_str_note() {
            assert_eq!(CipherType::from_str("note"), Ok(CipherType::SecureNote));
            assert_eq!(CipherType::from_str("NOTE"), Ok(CipherType::SecureNote));
            assert_eq!(
                CipherType::from_str("securenote"),
                Ok(CipherType::SecureNote)
            );
            assert_eq!(
                CipherType::from_str("SecureNote"),
                Ok(CipherType::SecureNote)
            );
            assert_eq!(CipherType::from_str("2"), Ok(CipherType::SecureNote));
        }

        #[test]
        fn test_cipher_type_from_str_card() {
            assert_eq!(CipherType::from_str("card"), Ok(CipherType::Card));
            assert_eq!(CipherType::from_str("CARD"), Ok(CipherType::Card));
            assert_eq!(CipherType::from_str("Card"), Ok(CipherType::Card));
            assert_eq!(CipherType::from_str("3"), Ok(CipherType::Card));
        }

        #[test]
        fn test_cipher_type_from_str_identity() {
            assert_eq!(CipherType::from_str("identity"), Ok(CipherType::Identity));
            assert_eq!(CipherType::from_str("IDENTITY"), Ok(CipherType::Identity));
            assert_eq!(CipherType::from_str("Identity"), Ok(CipherType::Identity));
            assert_eq!(CipherType::from_str("4"), Ok(CipherType::Identity));
        }

        #[test]
        fn test_cipher_type_from_str_ssh() {
            assert_eq!(CipherType::from_str("ssh"), Ok(CipherType::SshKey));
            assert_eq!(CipherType::from_str("SSH"), Ok(CipherType::SshKey));
            assert_eq!(CipherType::from_str("Ssh"), Ok(CipherType::SshKey));
            assert_eq!(CipherType::from_str("sshkey"), Ok(CipherType::SshKey));
            assert_eq!(CipherType::from_str("sshKey"), Ok(CipherType::SshKey));
            assert_eq!(CipherType::from_str("5"), Ok(CipherType::SshKey));
            assert_eq!(CipherType::from_str("6"), Ok(CipherType::SshKey));
        }

        #[test]
        fn test_cipher_type_from_str_invalid() {
            assert!(CipherType::from_str("invalid").is_err());
            assert!(CipherType::from_str("").is_err());
            assert!(CipherType::from_str("0").is_err());
            assert!(CipherType::from_str("7").is_err());
            assert!(CipherType::from_str("password").is_err());
        }

        #[test]
        fn test_cipher_type_values() {
            assert_eq!(CipherType::Login as u8, 1);
            assert_eq!(CipherType::SecureNote as u8, 2);
            assert_eq!(CipherType::Card as u8, 3);
            assert_eq!(CipherType::Identity as u8, 4);
            assert_eq!(CipherType::SshKey as u8, 5);
        }
    }

    // Cipher tests
    mod cipher_tests {
        use super::*;

        fn create_test_cipher() -> Cipher {
            Cipher {
                id: CipherId::new("test-id".to_string()).unwrap(),
                organization_id: None,
                deleted_date: None,
                name: Some("encrypted-name".to_string()),
                notes: Some("encrypted-notes".to_string()),
                folder_id: None,
                collection_ids: Vec::new(),
                fields: Some(vec![FieldData {
                    name: Some("field-name".to_string()),
                    value: Some("field-value".to_string()),
                    r#type: FieldType::Text,
                }]),
                data: None,
                cipher_data: Some(CipherData::Login(LoginData {
                    username: Some("encrypted-username".to_string()),
                    password: Some("encrypted-password".to_string()),
                    totp: None,
                    uris: Some(vec![UriData {
                        uri: Some("encrypted-uri".to_string()),
                        r#match: None,
                    }]),
                })),
            }
        }

        fn create_cipher_with_nested_data() -> Cipher {
            Cipher {
                id: CipherId::new("test-id".to_string()).unwrap(),
                organization_id: None,
                deleted_date: None,
                name: None,
                notes: None,
                folder_id: None,
                collection_ids: Vec::new(),
                fields: None,
                data: Some(NestedCipherData {
                    name: Some("nested-name".to_string()),
                    notes: Some("nested-notes".to_string()),
                    username: Some("nested-username".to_string()),
                    password: Some("nested-password".to_string()),
                    totp: None,
                    uri: Some("nested-uri".to_string()),
                    uris: None,
                    fields: Some(vec![FieldData {
                        name: Some("nested-field".to_string()),
                        value: Some("nested-value".to_string()),
                        r#type: FieldType::Hidden,
                    }]),
                }),
                cipher_data: Some(CipherData::Login(LoginData {
                    username: None,
                    password: None,
                    totp: None,
                    uris: None,
                })),
            }
        }

        #[test]
        fn test_cipher_type_is_enum() {
            let cipher = create_test_cipher();
            assert_eq!(
                cipher.cipher_data.as_ref().map(|cd| cd.cipher_type()),
                Some(CipherType::Login)
            );
        }

        #[test]
        fn test_get_name_from_direct_field() {
            let cipher = create_test_cipher();
            assert_eq!(cipher.get_name(), Some("encrypted-name"));
        }

        #[test]
        fn test_get_name_from_nested_data() {
            let cipher = create_cipher_with_nested_data();
            assert_eq!(cipher.get_name(), Some("nested-name"));
        }

        #[test]
        fn test_get_name_prefers_direct_over_nested() {
            let mut cipher = create_cipher_with_nested_data();
            cipher.name = Some("direct-name".to_string());
            assert_eq!(cipher.get_name(), Some("direct-name"));
        }

        #[test]
        fn test_get_name_none() {
            let cipher = Cipher {
                id: CipherId::new("test".to_string()).unwrap(),
                organization_id: None,
                deleted_date: None,
                name: None,
                notes: None,
                folder_id: None,
                collection_ids: Vec::new(),
                fields: None,
                data: None,
                cipher_data: Some(CipherData::Login(LoginData {
                    username: None,
                    password: None,
                    totp: None,
                    uris: None,
                })),
            };
            assert_eq!(cipher.get_name(), None);
        }

        #[test]
        fn test_get_username_from_login() {
            let cipher = create_test_cipher();
            assert_eq!(cipher.get_username(), Some("encrypted-username"));
        }

        #[test]
        fn test_get_username_from_nested_data() {
            let cipher = create_cipher_with_nested_data();
            assert_eq!(cipher.get_username(), Some("nested-username"));
        }

        #[test]
        fn test_get_password_from_login() {
            let cipher = create_test_cipher();
            assert_eq!(cipher.get_password(), Some("encrypted-password"));
        }

        #[test]
        fn test_get_password_from_nested_data() {
            let cipher = create_cipher_with_nested_data();
            assert_eq!(cipher.get_password(), Some("nested-password"));
        }

        #[test]
        fn test_get_uri_from_login_uris() {
            let cipher = create_test_cipher();
            assert_eq!(cipher.get_uri(), Some("encrypted-uri"));
        }

        #[test]
        fn test_get_uri_from_nested_data_direct() {
            let cipher = create_cipher_with_nested_data();
            assert_eq!(cipher.get_uri(), Some("nested-uri"));
        }

        #[test]
        fn test_get_uri_from_nested_uris_array() {
            let cipher = Cipher {
                id: CipherId::new("test".to_string()).unwrap(),
                organization_id: None,
                deleted_date: None,
                name: None,
                notes: None,
                folder_id: None,
                collection_ids: Vec::new(),
                fields: None,
                data: Some(NestedCipherData {
                    name: None,
                    notes: None,
                    username: None,
                    password: None,
                    totp: None,
                    uri: None,
                    uris: Some(vec![UriData {
                        uri: Some("uri-from-array".to_string()),
                        r#match: None,
                    }]),
                    fields: None,
                }),
                cipher_data: Some(CipherData::Login(LoginData {
                    username: None,
                    password: None,
                    totp: None,
                    uris: None,
                })),
            };
            assert_eq!(cipher.get_uri(), Some("uri-from-array"));
        }

        #[test]
        fn test_get_notes_from_direct_field() {
            let cipher = create_test_cipher();
            assert_eq!(cipher.get_notes(), Some("encrypted-notes"));
        }

        #[test]
        fn test_get_notes_from_nested_data() {
            let cipher = create_cipher_with_nested_data();
            assert_eq!(cipher.get_notes(), Some("nested-notes"));
        }

        #[test]
        fn test_get_fields_from_direct() {
            let cipher = create_test_cipher();
            let fields = cipher.get_fields().unwrap();
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].name, Some("field-name".to_string()));
        }

        #[test]
        fn test_get_fields_from_nested_data() {
            let cipher = create_cipher_with_nested_data();
            let fields = cipher.get_fields().unwrap();
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].name, Some("nested-field".to_string()));
        }
    }

    // Deserialization tests
    mod deserialization_tests {
        use super::*;

        #[test]
        fn test_token_response_deserialization() {
            let json = r#"{
                "access_token": "test-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "refresh-token",
                "Key": "encrypted-key",
                "KdfIterations": 600000
            }"#;

            let response: TokenResponse = serde_json::from_str(json).unwrap();
            assert_eq!(response.access_token, "test-token");
            assert_eq!(response.expires_in, 3600);
            assert_eq!(response.token_type, "Bearer");
            assert_eq!(response.refresh_token, Some("refresh-token".to_string()));
            assert_eq!(response.key, Some("encrypted-key".to_string()));
            assert_eq!(response.kdf_iterations, Some(600000));
        }

        #[test]
        fn test_token_response_lowercase_aliases() {
            let json = r#"{
                "access_token": "test-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "key": "encrypted-key",
                "kdfIterations": 100000
            }"#;

            let response: TokenResponse = serde_json::from_str(json).unwrap();
            assert_eq!(response.key, Some("encrypted-key".to_string()));
            assert_eq!(response.kdf_iterations, Some(100000));
        }

        #[test]
        fn test_cipher_deserialization_with_login() {
            let json = r#"{
                "Id": "cipher-123",
                "Type": 1,
                "Name": "My Login",
                "Login": {
                    "Username": "user@example.com",
                    "Password": "secret123",
                    "Uris": [
                        {"Uri": "https://example.com", "Match": 0}
                    ]
                }
            }"#;

            let cipher: Cipher = serde_json::from_str(json).unwrap();
            assert_eq!(cipher.id, "cipher-123");
            assert_eq!(
                cipher.cipher_data.as_ref().map(|cd| cd.cipher_type()),
                Some(CipherType::Login)
            );
            assert_eq!(cipher.get_name(), Some("My Login"));
            assert_eq!(cipher.get_username(), Some("user@example.com"));
            assert_eq!(cipher.get_password(), Some("secret123"));
            assert_eq!(cipher.get_uri(), Some("https://example.com"));
        }

        #[test]
        fn test_cipher_deserialization_with_nested_data() {
            let json = r#"{
                "id": "cipher-456",
                "type": 1,
                "data": {
                    "name": "Nested Login",
                    "username": "nested@example.com",
                    "password": "nestedpass",
                    "uri": "https://nested.com"
                }
            }"#;

            let cipher: Cipher = serde_json::from_str(json).unwrap();
            assert_eq!(cipher.id, "cipher-456");
            assert_eq!(cipher.get_name(), Some("Nested Login"));
            assert_eq!(cipher.get_username(), Some("nested@example.com"));
            assert_eq!(cipher.get_uri(), Some("https://nested.com"));
        }

        #[test]
        fn test_cipher_deserialization_with_organization() {
            let json = r#"{
                "Id": "cipher-789",
                "Type": 1,
                "OrganizationId": "org-123",
                "Name": "Org Item"
            }"#;

            let cipher: Cipher = serde_json::from_str(json).unwrap();
            assert_eq!(
                cipher.organization_id,
                Some(OrgId::new("org-123".to_string()).unwrap())
            );
        }

        #[test]
        fn test_sync_response_deserialization() {
            let json = r#"{
                "Ciphers": [],
                "Folders": [],
                "Collections": [],
                "Profile": {
                    "Id": "user-123",
                    "Email": "user@example.com",
                    "Name": "Test User",
                    "Organizations": []
                }
            }"#;

            let response: SyncResponse = serde_json::from_str(json).unwrap();
            assert!(response.ciphers.is_empty());
            assert!(response.folders.is_empty());
            assert!(response.collections.is_empty());
            assert_eq!(response.profile.email, "user@example.com");
        }

        #[test]
        fn test_sync_response_with_collections() {
            let json = r#"{
                "Ciphers": [],
                "Folders": [],
                "Collections": [
                    {"Id": "col-1", "Name": "encrypted-name", "OrganizationId": "org-1"},
                    {"Id": "col-2", "Name": "encrypted-name-2", "OrganizationId": "org-1"}
                ],
                "Profile": {
                    "Id": "user-123",
                    "Email": "user@example.com",
                    "Organizations": []
                }
            }"#;

            let response: SyncResponse = serde_json::from_str(json).unwrap();
            assert_eq!(response.collections.len(), 2);
            assert_eq!(response.collections[0].id, "col-1");
            assert_eq!(response.collections[0].organization_id, "org-1");
        }

        #[test]
        fn test_cipher_with_collection_ids() {
            let json = r#"{
                "Id": "cipher-abc",
                "Type": 1,
                "OrganizationId": "org-1",
                "CollectionIds": ["col-1", "col-2"],
                "Name": "Org Item"
            }"#;

            let cipher: Cipher = serde_json::from_str(json).unwrap();
            assert_eq!(cipher.collection_ids.len(), 2);
            assert_eq!(cipher.collection_ids[0], "col-1");
            assert_eq!(cipher.collection_ids[1], "col-2");
        }

        #[test]
        fn test_profile_with_organizations() {
            let json = r#"{
                "Id": "user-123",
                "Email": "user@example.com",
                "Organizations": [
                    {"Id": "org-1", "Name": "Org One", "Key": "org-key-1"},
                    {"Id": "org-2", "Name": "Org Two", "Key": "org-key-2"}
                ]
            }"#;

            let profile: Profile = serde_json::from_str(json).unwrap();
            assert_eq!(profile.organizations.len(), 2);
            assert_eq!(profile.organizations[0].id, "org-1");
            assert_eq!(profile.organizations[1].key, Some("org-key-2".to_string()));
        }

        #[test]
        fn test_field_data_types() {
            let json = r#"[
                {"Name": "text-field", "Value": "text-value", "Type": 0},
                {"Name": "hidden-field", "Value": "hidden-value", "Type": 1},
                {"Name": "bool-field", "Value": "true", "Type": 2},
                {"Name": "linked-field", "Value": "linked", "Type": 3}
            ]"#;

            let fields: Vec<FieldData> = serde_json::from_str(json).unwrap();
            assert_eq!(fields.len(), 4);
            assert_eq!(fields[0].r#type, FieldType::Text);
            assert_eq!(fields[1].r#type, FieldType::Hidden);
            assert_eq!(fields[2].r#type, FieldType::Boolean);
            assert_eq!(fields[3].r#type, FieldType::Linked);
        }

        #[test]
        fn test_field_data_missing_type_errors() {
            let json = r#"{"Name": "unknown-field", "Value": "secret-value"}"#;

            let result: Result<FieldData, _> = serde_json::from_str(json);
            assert!(result.is_err(), "missing FieldType should error");
        }

        #[test]
        fn test_field_data_invalid_type_errors() {
            let json = r#"{"Name": "unknown-field", "Value": "secret-value", "Type": "invalid"}"#;

            let result: Result<FieldData, _> = serde_json::from_str(json);
            assert!(result.is_err(), "invalid FieldType should error");
        }

        #[test]
        fn test_cipher_with_invalid_field_type_errors() {
            let json = r#"{
                "Id": "cipher-with-bad-field",
                "Type": 1,
                "Name": "Encrypted Name",
                "Fields": [
                    {"Name": "api-key", "Value": "secret-value", "Type": "invalid"}
                ]
            }"#;

            let result: Result<Cipher, _> = serde_json::from_str(json);
            assert!(
                result.is_err(),
                "cipher with invalid FieldType should error"
            );
        }

        #[test]
        fn test_card_data_deserialization() {
            let json = r#"{
                "CardholderName": "John Doe",
                "Brand": "Visa",
                "Number": "4111111111111111",
                "ExpMonth": "12",
                "ExpYear": "2025",
                "Code": "123"
            }"#;

            let card: CardData = serde_json::from_str(json).unwrap();
            assert_eq!(card.cardholder_name, Some("John Doe".to_string()));
            assert_eq!(card.brand, Some("Visa".to_string()));
            assert_eq!(card.code, Some("123".to_string()));
        }

        #[test]
        fn test_identity_data_deserialization() {
            let json = r#"{
                "Title": "Mr",
                "FirstName": "John",
                "LastName": "Doe",
                "Email": "john@example.com",
                "Phone": "555-1234"
            }"#;

            let identity: IdentityData = serde_json::from_str(json).unwrap();
            assert_eq!(identity.title, Some("Mr".to_string()));
            assert_eq!(identity.first_name, Some("John".to_string()));
            assert_eq!(identity.email, Some("john@example.com".to_string()));
        }
    }

    // Serialization tests
    mod serialization_tests {
        use super::*;

        #[test]
        fn test_cipher_output_serialization() {
            let output = CipherOutput {
                id: "test-id".to_string(),
                cipher_type: "login".to_string(),
                name: "Test Login".to_string(),
                username: Some("user@example.com".to_string()),
                password: Some("secret".to_string()),
                uri: Some("https://example.com".to_string()),
                notes: None,
                fields: None,
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
            };

            let json = serde_json::to_string(&output).unwrap();
            assert!(json.contains("\"id\":\"test-id\""));
            assert!(json.contains("\"type\":\"login\"")); // Note: uses "type" due to rename
            assert!(json.contains("\"username\":\"user@example.com\""));
            // Notes should be skipped because it's None
            assert!(!json.contains("\"notes\""));
        }

        #[test]
        fn test_cipher_output_with_fields() {
            let output = CipherOutput {
                id: "test-id".to_string(),
                cipher_type: "login".to_string(),
                name: "Test".to_string(),
                username: None,
                password: None,
                uri: None,
                notes: None,
                fields: Some(vec![FieldOutput {
                    name: "api-key".to_string(),
                    value: "secret-key".to_string(),
                    hidden: true,
                }]),
                ssh_public_key: None,
                ssh_private_key: None,
                ssh_fingerprint: None,
            };

            let json = serde_json::to_string(&output).unwrap();
            assert!(json.contains("\"fields\""));
            assert!(json.contains("\"api-key\""));
            assert!(json.contains("\"hidden\":true"));
        }

        #[test]
        fn test_cipher_type_serialization() {
            let cipher_type = CipherType::Login;
            let json = serde_json::to_string(&cipher_type).unwrap();
            assert_eq!(json, "\"Login\"");
        }

        #[test]
        fn test_cipher_type_deserialization_from_u8() {
            let cipher_json = r#"{"Id": "test", "Type": 1}"#;
            let cipher: Cipher = serde_json::from_str(cipher_json).unwrap();
            assert_eq!(
                cipher.cipher_data.as_ref().map(|cd| cd.cipher_type()),
                Some(CipherType::Login)
            );
        }
    }
}
